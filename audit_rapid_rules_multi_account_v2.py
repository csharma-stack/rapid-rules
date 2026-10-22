#!/usr/bin/env python3
"""
Akamai Rapid Rules Customer-Managed Audit Tool (Multi-Account & Universal)
=========================================================================
Audits Akamai Security Configurations across one, multiple, or all accounts
to identify security policies where Rapid Rules are customer-managed:
  1. Policy-level defaultAction is explicitly set by the customer (e.g., 'alert', 'deny', 'none')
     rather than 'akamai_managed'.
  2. Individual Rapid Rules have been explicitly pinned and locked ('lock': True).

Policies where defaultAction is 'akamai_managed' and no rules are locked are
strictly classified as Akamai-managed and are excluded from customer-managed findings.

Automatically timestamps and names the output CSV report based on the audited
account(s) and execution date & time.
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime
import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc

# Default configuration settings
DEFAULT_EDGERC_PATH = "~/.edgerc"
DEFAULT_EDGERC_SECTION = "default"

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}


def init_session(edgerc_path, section):
    """Initializes and returns an EdgeGrid authenticated requests session."""
    expanded_path = os.path.expanduser(edgerc_path)
    if not os.path.exists(expanded_path):
        sys.exit(f"[-] Credentials file not found at: {expanded_path}")
    try:
        rc = EdgeRc(expanded_path)
        base_url = f"https://{rc.get(section, 'host')}"
        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(rc, section)
        return session, base_url
    except Exception as err:
        sys.exit(f"[-] Authentication configuration error: {err}")


def send_request_with_retry(session, method, url, params=None, max_retries=3):
    """Sends HTTP requests with backoff retry for rate limits (429) and server errors (5xx)."""
    resp = None
    for attempt in range(max_retries):
        try:
            resp = session.request(method, url, headers=HEADERS, params=params, timeout=30)
            if resp.status_code == 429 or resp.status_code >= 500:
                wait_time = 2 ** (attempt + 1)
                time.sleep(wait_time)
                continue
            return resp
        except requests.RequestException:
            time.sleep(2)
    return resp


def get_all_account_switch_keys(session, base_url):
    """Fetches all account switch keys accessible by this API client via IAM API."""
    url = f"{base_url}/identity-management/v3/api-clients/self/account-switch-keys"
    resp = send_request_with_retry(session, "GET", url)
    if not resp or resp.status_code != 200:
        err = resp.text if resp else "Connection error"
        sys.exit(f"[-] Failed to retrieve accessible accounts via IAM API (HTTP {resp.status_code if resp else 'N/A'}): {err}\n"
                 f"    Verify that your API client has permissions for Identity and Access Management.")
    data = resp.json()
    keys = []
    for item in data:
        key = item.get("accountSwitchKey")
        name = item.get("accountName", "Unknown")
        if key:
            keys.append((key, name))
    return keys


def get_configurations(session, base_url, account_key):
    """Fetches all security configurations in the target account."""
    url = f"{base_url}/appsec/v1/configs"
    params = {"accountSwitchKey": account_key}
    resp = send_request_with_retry(session, "GET", url, params=params)
    if not resp or resp.status_code != 200:
        err = resp.text if resp else "Connection timeout"
        print(f"[-] Failed to fetch configurations for account {account_key}: {err}")
        return []
    return resp.json().get("configurations") or []


def get_policies(session, base_url, config_id, version, account_key):
    """Retrieves all security policies for a configuration version."""
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies"
    params = {"accountSwitchKey": account_key}
    resp = send_request_with_retry(session, "GET", url, params=params)
    if not resp or resp.status_code != 200:
        return []
    data = resp.json()
    return data.get("policies") or data.get("securityPolicies") or (data if isinstance(data, list) else [])


def get_policy_default_action(session, base_url, config_id, version, policy_id, account_key):
    """
    Retrieves the Rapid Rules policy-level default action.
    Returns:
      - Raw action string (e.g. 'akamai_managed', 'alert', 'deny', 'none')
      - 'WAF_DISABLED' if application layer control is not enabled (HTTP 400)
      - 'HTTP_500_UNSUPPORTED' if Akamai encounters an unhandled internal error (HTTP 500)
      - 'ERROR' on unexpected failure
    """
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules/action"
    params = {"accountSwitchKey": account_key}
    resp = send_request_with_retry(session, "GET", url, params=params)

    if resp and resp.status_code == 200:
        return resp.json().get("action", "unknown")

    if resp and resp.status_code == 400 and "Application layer control isn't enabled" in resp.text:
        return "WAF_DISABLED"

    if resp and resp.status_code >= 500:
        return "HTTP_500_UNSUPPORTED"

    return "ERROR"


def get_rapid_rules(session, base_url, config_id, version, policy_id, account_key):
    """Retrieves all individual Rapid Rules configured under a policy."""
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules"
    params = {"accountSwitchKey": account_key}
    resp = send_request_with_retry(session, "GET", url, params=params)

    if resp and resp.status_code == 200:
        data = resp.json()
        return data.get("policyRules") or data.get("rapidRules") or []
    return []


def is_rule_locked(rule_dict):
    """
    Determines if a rule has been customer-locked.
    In Akamai Rapid Rules:
    - lock == True (or 'true'): Rule is locked to its action by customer.
    - lock == False (or None): Rule dynamically follows Akamai threat research updates.
    """
    val = rule_dict.get("lock")
    if val is True:
        return True
    if isinstance(val, str) and val.strip().lower() in ["true", "1", "yes"]:
        return True
    return False


def is_action_akamai_managed(action_str):
    """Checks if the default action represents automated Akamai management."""
    if not action_str:
        return False
    normalized = str(action_str).strip().lower().replace("-", "_").replace(" ", "_")
    return normalized == "akamai_managed"


def audit_account(session, base_url, account_key, account_name, csv_writer, csv_file, custom_defaults_only=False):
    """
    Audits a single account and writes customer-managed policies to CSV.
    """
    print(f"\n=======================================================")
    print(f"[*] Auditing Account: {account_name} ({account_key})")
    print(f"=======================================================")

    configs = get_configurations(session, base_url, account_key)
    print(f"[+] Discovered {len(configs)} configurations in account {account_key}.")

    customer_managed_count = 0
    akamai_managed_skipped = 0
    skipped_waf_disabled = 0
    logged_500_errors = 0

    for cfg in configs:
        config_id = cfg.get("id") or cfg.get("configId")
        config_name = cfg.get("name", "Unnamed Config")

        prod_version = cfg.get("production", {}).get("version")
        staging_version = cfg.get("staging", {}).get("version")
        target_version = prod_version or staging_version or cfg.get("latestVersion")

        if not target_version:
            continue

        env_label = "PROD" if target_version == prod_version else ("STAGING" if target_version == staging_version else "DRAFT")
        policies = get_policies(session, base_url, config_id, target_version, account_key)

        for pol in policies:
            policy_id = pol.get("policyId") or pol.get("id")
            policy_name = pol.get("policyName") or pol.get("name") or policy_id

            default_action = get_policy_default_action(session, base_url, config_id, target_version, policy_id, account_key)

            # Skip non-WAF policies
            if default_action == "WAF_DISABLED":
                skipped_waf_disabled += 1
                continue

            # Record backend 500 error policies for audit review and skip child queries
            if default_action == "HTTP_500_UNSUPPORTED":
                logged_500_errors += 1
                print(f"    [!] Policy {policy_name} ({policy_id}): Akamai backend HTTP 500. Logged.")
                csv_writer.writerow({
                    "account_switch_key": account_key,
                    "account_name": account_name,
                    "config_id": config_id,
                    "config_name": config_name,
                    "environment": env_label,
                    "version": target_version,
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "management_type": "BACKEND_ERROR",
                    "default_action": "HTTP_500_BACKEND_ERROR",
                    "custom_rule_count": 0,
                    "rule_details": "Akamai internal error (Rapid Rules uninitialized/unsupported on backend)"
                })
                csv_file.flush()
                continue

            # Check individual rules for explicit customer locks
            rules = get_rapid_rules(session, base_url, config_id, target_version, policy_id, account_key)
            locked_rules = []

            for r in rules:
                if is_rule_locked(r):
                    locked_rules.append({
                        "ruleId": r.get("ruleId") or r.get("id"),
                        "action": r.get("action"),
                        "locked": True
                    })

            akamai_managed_default = is_action_akamai_managed(default_action)
            has_locked_rules = len(locked_rules) > 0

            # -------------------------------------------------------------
            # STRICT FILTERING LOGIC
            # -------------------------------------------------------------
            # Case 1: Purely Akamai-Managed (default is akamai_managed and NO locked rules)
            if akamai_managed_default and not has_locked_rules:
                akamai_managed_skipped += 1
                continue

            # Case 2: Policy default is customer-managed (alert, deny, none, etc.)
            if not akamai_managed_default and default_action not in ["ERROR", "UNKNOWN"]:
                customer_managed_count += 1
                management_type = "CUSTOMER_MANAGED_POLICY_DEFAULT"
                print(f"[!] Customer-Managed Found: {config_name} ({config_id}) | Policy: {policy_name} ({policy_id})")
                print(f"    Env: {env_label} (v{target_version}) | Default Action: {default_action} | Locked Rules: {len(locked_rules)}")

                csv_writer.writerow({
                    "account_switch_key": account_key,
                    "account_name": account_name,
                    "config_id": config_id,
                    "config_name": config_name,
                    "environment": env_label,
                    "version": target_version,
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "management_type": management_type,
                    "default_action": default_action,
                    "custom_rule_count": len(locked_rules),
                    "rule_details": "; ".join([f"ID:{r['ruleId']}(act:{r['action']},locked:{r['locked']})" for r in locked_rules]) if locked_rules else "None (Policy Default Applies)"
                })
                csv_file.flush()
                continue

            # Case 3: Policy default is akamai_managed, BUT individual rules are locked by customer
            if akamai_managed_default and has_locked_rules and not custom_defaults_only:
                customer_managed_count += 1
                management_type = "CUSTOMER_LOCKED_RULES_ONLY"
                print(f"[!] Customer-Locked Rules Found: {config_name} ({config_id}) | Policy: {policy_name} ({policy_id})")
                print(f"    Env: {env_label} (v{target_version}) | Policy Default: akamai_managed | Customer-Locked Rules: {len(locked_rules)}")

                csv_writer.writerow({
                    "account_switch_key": account_key,
                    "account_name": account_name,
                    "config_id": config_id,
                    "config_name": config_name,
                    "environment": env_label,
                    "version": target_version,
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "management_type": management_type,
                    "default_action": default_action,
                    "custom_rule_count": len(locked_rules),
                    "rule_details": "; ".join([f"ID:{r['ruleId']}(act:{r['action']},locked:{r['locked']})" for r in locked_rules])
                })
                csv_file.flush()
                continue

    print(f"[*] Account summary:")
    print(f"    - Customer-Managed / Locked Policies Found : {customer_managed_count}")
    print(f"    - Purely Akamai-Managed Policies Skipped   : {akamai_managed_skipped}")
    print(f"    - Akamai Backend 500 Policies Logged       : {logged_500_errors}")
    print(f"    - Non-WAF Policies Skipped                 : {skipped_waf_disabled}")
    return customer_managed_count, akamai_managed_skipped, logged_500_errors, skipped_waf_disabled


def parse_accounts_argument(accounts_input):
    """Parses accounts argument supporting comma-separated strings or list of strings."""
    parsed = []
    for item in accounts_input:
        for sub_item in item.split(","):
            cleaned = sub_item.strip()
            if cleaned and cleaned not in parsed:
                parsed.append(cleaned)
    return parsed


def sanitize_filename_token(token):
    """Replaces unsafe characters for filenames."""
    return token.replace(":", "_").replace("/", "_").replace("\\", "_").replace(" ", "_")


def build_output_csv_filename(args_output, target_accounts, is_all):
    """
    Constructs the output CSV filename based on Account and Date/Time:
    - Custom override if --output is provided
    - customer_managed_rapid_rules_<ACCOUNT>_<YYYYMMDD_HHMMSS>.csv (single account)
    - customer_managed_rapid_rules_<ACC1>_<ACC2>_<YYYYMMDD_HHMMSS>.csv (2-3 accounts)
    - customer_managed_rapid_rules_multi_account_<YYYYMMDD_HHMMSS>.csv (>3 accounts)
    - customer_managed_rapid_rules_ALL_ACCOUNTS_<YYYYMMDD_HHMMSS>.csv (--all)
    """
    if args_output:
        return args_output

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if is_all:
        return f"customer_managed_rapid_rules_ALL_ACCOUNTS_{timestamp}.csv"

    if len(target_accounts) == 1:
        clean_key = sanitize_filename_token(target_accounts[0][0])
        return f"customer_managed_rapid_rules_{clean_key}_{timestamp}.csv"
    elif len(target_accounts) <= 3:
        keys_str = "_".join(sanitize_filename_token(acc[0]) for acc in target_accounts)
        return f"customer_managed_rapid_rules_{keys_str}_{timestamp}.csv"
    else:
        return f"customer_managed_rapid_rules_multi_account_{timestamp}.csv"


def main():
    parser = argparse.ArgumentParser(
        description="Audit Akamai Rapid Rules for Customer-Managed policies across single, multiple, or all accounts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run for a single account (e.g. Morgan Stanley):
  python audit_rapid_rules_multi_account_v2.py -a "1-1DJL"
  # Output file: customer_managed_rapid_rules_1-1DJL_20261021_144500.csv

  # Run for multiple accounts (comma-separated):
  python audit_rapid_rules_multi_account_v2.py -a "1-1DJL,1-2ABC,1-3XYZ"

  # Run for multiple accounts (multiple -a flags):
  python audit_rapid_rules_multi_account_v2.py -a "1-1DJL" -a "1-2ABC"

  # Run across ALL accounts accessible by the credential:
  python audit_rapid_rules_multi_account_v2.py --all
  # Output file: customer_managed_rapid_rules_ALL_ACCOUNTS_20261021_144500.csv

  # Audit ONLY policies where defaultAction is customized (exclude locked-only rules):
  python audit_rapid_rules_multi_account_v2.py -a "1-1DJL" --custom-defaults-only

  # Custom credentials profile and custom output file:
  python audit_rapid_rules_multi_account_v2.py -a "1-1DJL" -s "prod_sec" -o "morgan_stanley_audit.csv"
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--account", "-a",
        action="append",
        help="Account Switch Key(s). Can be specified multiple times or as comma-separated values (e.g., -a '1-1DJL,1-2ABC')."
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Automatically discover and audit ALL accounts accessible by this API client."
    )

    parser.add_argument(
        "--custom-defaults-only",
        action="store_true",
        help="Filter strictly for policies where defaultAction is customer-managed (alert, deny, etc.), ignoring policies that are akamai_managed with locked rules."
    )
    parser.add_argument(
        "--edgerc", "-e",
        type=str,
        default=DEFAULT_EDGERC_PATH,
        help=f"Path to .edgerc credentials file (default: {DEFAULT_EDGERC_PATH})"
    )
    parser.add_argument(
        "--section", "-s",
        type=str,
        default=DEFAULT_EDGERC_SECTION,
        help=f"Section header inside .edgerc (default: {DEFAULT_EDGERC_SECTION})"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Custom output CSV filename (default: named after Account and Date/Time)"
    )

    args = parser.parse_args()

    session, base_url = init_session(args.edgerc, args.section)

    target_accounts = []

    if args.all:
        print("[*] Retrieving all accessible accounts via Akamai IAM API...")
        all_keys = get_all_account_switch_keys(session, base_url)
        if not all_keys:
            sys.exit("[-] No account switch keys returned for this credential.")
        print(f"[+] Discovered {len(all_keys)} accessible accounts.")
        target_accounts = all_keys
    else:
        account_keys = parse_accounts_argument(args.account)
        if not account_keys:
            sys.exit("[-] Error: At least one Account Switch Key must be provided.")
        target_accounts = [(k, k) for k in account_keys]

    output_csv = build_output_csv_filename(args.output, target_accounts, args.all)

    print(f"[*] Total Accounts to Audit : {len(target_accounts)}")
    print(f"[*] Real-time Output CSV    : {output_csv}\n")

    fieldnames = [
        "account_switch_key", "account_name", "config_id", "config_name",
        "environment", "version", "policy_id", "policy_name",
        "management_type", "default_action", "custom_rule_count", "rule_details"
    ]

    total_findings = 0
    total_akamai_managed_skipped = 0
    total_500s = 0
    total_waf_skipped = 0

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        csv_file.flush()

        for idx, (acc_key, acc_name) in enumerate(target_accounts, 1):
            print(f"\n[{idx}/{len(target_accounts)}] Commencing scan for {acc_name} ({acc_key})...")
            findings, skipped_ak, err_500s, waf_skips = audit_account(
                session, base_url, acc_key, acc_name, writer, csv_file,
                custom_defaults_only=args.custom_defaults_only
            )
            total_findings += findings
            total_akamai_managed_skipped += skipped_ak
            total_500s += err_500s
            total_waf_skipped += waf_skips

    print("\n" + "=" * 65)
    print("UNIVERSAL AUDIT COMPLETE")
    print(f"  Total Accounts Scanned                   : {len(target_accounts)}")
    print(f"  Customer-Managed Policies / Overrides    : {total_findings}")
    print(f"  Purely Akamai-Managed Policies Skipped   : {total_akamai_managed_skipped}")
    print(f"  Akamai Backend 500 Policies Logged       : {total_500s}")
    print(f"  Non-WAF Policies Skipped                 : {total_waf_skipped}")
    print(f"  Master Report CSV                        : {output_csv}")
    print("=" * 65)


if __name__ == "__main__":
    main()
