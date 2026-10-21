import csv
import os
import sys
import time
import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc

# ==============================================================================
# CONFIGURATION SECTION
# ==============================================================================
# 1. Target Account Switch Key (e.g., "1-1DJL", "F-AC-123456")
#    Set to "" or None to run against your default credential's account.
ACCOUNT_SWITCH_KEY = "" 

# 2. EdgeGrid Credentials
EDGERC_PATH = os.path.expanduser("~/.edgerc")
EDGERC_SECTION = "default"

# 3. Output File Destination
#    Automatically names the file based on the target account.
OUTPUT_CSV = f"rapid_rules_audit_{ACCOUNT_SWITCH_KEY.replace(':', '_') if ACCOUNT_SWITCH_KEY else 'default_account'}.csv"
# ==============================================================================

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def init_session(edgerc_path, section):
    """Initializes the EdgeGrid authenticated requests session."""
    if not os.path.exists(edgerc_path):
        sys.exit(f"[-] Credentials file not found at: {edgerc_path}")
    try:
        rc = EdgeRc(edgerc_path)
        base_url = f"https://{rc.get(section, 'host')}"
        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(rc, section)
        return session, base_url
    except Exception as err:
        sys.exit(f"[-] Authentication configuration error: {err}")

def send_request_with_retry(session, method, url, params=None, max_retries=3):
    """Retries transient 429 (Rate Limit) and 5xx (Server) errors with exponential backoff."""
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

def get_query_params():
    """Appends accountSwitchKey parameter to scope calls to the target account."""
    return {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}

def get_configurations(session, base_url):
    url = f"{base_url}/appsec/v1/configs"
    resp = send_request_with_retry(session, "GET", url, params=get_query_params())
    if not resp or resp.status_code != 200:
        err = resp.text if resp else "Connection timeout"
        sys.exit(f"[-] Failed to fetch configurations: {err}")
    return resp.json().get("configurations") or []

def get_policies(session, base_url, config_id, version):
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies"
    resp = send_request_with_retry(session, "GET", url, params=get_query_params())
    if not resp or resp.status_code != 200:
        return []
    data = resp.json()
    return data.get("policies") or data.get("securityPolicies") or (data if isinstance(data, list) else [])

def get_policy_default_action(session, base_url, config_id, version, policy_id):
    """
    Evaluates policy default action with failover logic:
      - 'akamai_managed', 'alert', 'deny', etc.
      - 'WAF_DISABLED': HTTP 400 when application layer control is turned off.
      - 'HTTP_500_UNSUPPORTED': Akamai internal server error for legacy/uninitialized policies.
    """
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules/action"
    resp = send_request_with_retry(session, "GET", url, params=get_query_params())

    if resp and resp.status_code == 200:
        return resp.json().get("action", "unknown")

    if resp and resp.status_code == 400 and "Application layer control isn't enabled" in resp.text:
        return "WAF_DISABLED"

    if resp and resp.status_code >= 500:
        return "HTTP_500_UNSUPPORTED"

    return "ERROR"

def get_rapid_rules(session, base_url, config_id, version, policy_id):
    url = f"{base_url}/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules"
    resp = send_request_with_retry(session, "GET", url, params=get_query_params())

    if resp and resp.status_code == 200:
        data = resp.json()
        return data.get("policyRules") or data.get("rapidRules") or []
    return []

def main():
    target_label = ACCOUNT_SWITCH_KEY if ACCOUNT_SWITCH_KEY else "Default Credential Account"
    print(f"[*] Starting audit for Account: {target_label}")
    print(f"[*] Real-time CSV output: {OUTPUT_CSV}\n")

    session, base_url = init_session(EDGERC_PATH, EDGERC_SECTION)
    configs = get_configurations(session, base_url)

    print(f"[+] Connected. Total configurations discovered: {len(configs)}\n")

    fieldnames = [
        "account_switch_key", "config_id", "config_name", "environment",
        "version", "policy_id", "policy_name", "default_action",
        "custom_rule_count", "rule_details"
    ]

    total_findings = 0
    skipped_waf_disabled = 0
    logged_500_errors = 0

    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        csv_file.flush()

        for cfg in configs:
            config_id = cfg.get("id") or cfg.get("configId")
            config_name = cfg.get("name", "Unnamed Config")

            prod_version = cfg.get("production", {}).get("version")
            staging_version = cfg.get("staging", {}).get("version")
            target_version = prod_version or staging_version or cfg.get("latestVersion")

            if not target_version:
                continue

            env_label = "PROD" if target_version == prod_version else ("STAGING" if target_version == staging_version else "DRAFT")
            policies = get_policies(session, base_url, config_id, target_version)

            for pol in policies:
                policy_id = pol.get("policyId") or pol.get("id")
                policy_name = pol.get("policyName") or pol.get("name") or policy_id

                default_action = get_policy_default_action(session, base_url, config_id, target_version, policy_id)

                # Failover 1: Gracefully skip non-WAF policies
                if default_action == "WAF_DISABLED":
                    skipped_waf_disabled += 1
                    continue

                # Failover 2: Record backend 500 errors and avoid rule querying
                if default_action == "HTTP_500_UNSUPPORTED":
                    logged_500_errors += 1
                    print(f"    [!] Policy {policy_name} ({policy_id}): Akamai backend returned HTTP 500. Logged to CSV.")
                    writer.writerow({
                        "account_switch_key": target_label,
                        "config_id": config_id,
                        "config_name": config_name,
                        "environment": env_label,
                        "version": target_version,
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "default_action": "HTTP_500_BACKEND_ERROR",
                        "custom_rule_count": 0,
                        "rule_details": "Akamai internal server error (Rapid Rules uninitialized or unsupported)"
                    })
                    csv_file.flush()
                    continue

                # Fetch individual rules
                rules = get_rapid_rules(session, base_url, config_id, target_version, policy_id)
                customized_rules = []

                for r in rules:
                    rule_id = r.get("ruleId") or r.get("id")
                    rule_action = r.get("action")
                    is_locked = r.get("lock", False)

                    if is_locked or (default_action == "akamai_managed" and rule_action != "akamai_managed"):
                        customized_rules.append({
                            "ruleId": rule_id,
                            "action": rule_action,
                            "locked": is_locked
                        })

                is_custom_default = (default_action not in ["akamai_managed", "ERROR"])
                has_overrides = len(customized_rules) > 0

                if is_custom_default or has_overrides:
                    total_findings += 1
                    print(f"[!] Customer-Managed Found: {config_name} ({config_id}) | Policy: {policy_name} ({policy_id})")
                    print(f"    Env: {env_label} (v{target_version}) | Default: {default_action} | Overrides: {len(customized_rules)}")

                    writer.writerow({
                        "account_switch_key": target_label,
                        "config_id": config_id,
                        "config_name": config_name,
                        "environment": env_label,
                        "version": target_version,
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "default_action": default_action,
                        "custom_rule_count": len(customized_rules),
                        "rule_details": "; ".join([f"ID:{r['ruleId']}(act:{r['action']},locked:{r['locked']})" for r in customized_rules])
                    })
                    csv_file.flush()

    print("\n" + "=" * 55)
    print("Audit Complete:")
    print(f"  Customer-Managed Policies Found : {total_findings}")
    print(f"  Akamai Backend 500 Policies     : {logged_500_errors}")
    print(f"  Non-WAF Policies Skipped        : {skipped_waf_disabled}")
    print(f"  Output CSV                     : {OUTPUT_CSV}")
    print("=" * 55)

if __name__ == "__main__":
    main()