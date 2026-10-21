#!/usr/bin/env python3
"""
Akamai Rapid Rules Bulk Update Tool (Account-Wide)
Traverses all Security Configurations and Policies in an account to update Rapid Rules to 'deny',
with optional action locking across future rule versions.
"""

import os
import sys
import time
import argparse
import requests

try:
    from akamai.edgegrid import EdgeGridAuth, EdgeRc
except ImportError:
    print("Error: Required library 'edgegrid-python' is not installed.")
    print("Install it with: pip install edgegrid-python requests")
    sys.exit(1)


class AkamaiRapidRulesUpdater:
    def __init__(self, edgerc_path="~/.edgerc", section="default", account_id=None, create_version=False, lock_action=False):
        self.edgerc_path = os.path.expanduser(edgerc_path)
        self.section = section
        self.account_id = account_id
        self.create_version = create_version
        self.lock_action = lock_action
        
        # Initialize EdgeGrid auth session
        try:
            edgerc = EdgeRc(self.edgerc_path)
            self.base_url = f"https://{edgerc.get(self.section, 'host')}"
            self.session = requests.Session()
            self.session.auth = EdgeGridAuth.from_edgerc(edgerc, self.section)
        except Exception as e:
            print(f"[FATAL] Failed to initialize EdgeGrid authentication: {e}")
            sys.exit(1)

        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def api_request(self, method, endpoint, payload=None, max_retries=5):
        """Executes API request with exponential backoff and rate-limit handling."""
        url = f"{self.base_url}{endpoint}"
        params = {}
        if self.account_id:
            params["accountSwitchKey"] = self.account_id

        for attempt in range(1, max_retries + 1):
            try:
                if method.upper() == "GET":
                    resp = self.session.get(url, headers=self.headers, params=params, timeout=30)
                elif method.upper() == "POST":
                    resp = self.session.post(url, headers=self.headers, params=params, json=payload, timeout=30)
                elif method.upper() == "PUT":
                    resp = self.session.put(url, headers=self.headers, params=params, json=payload, timeout=30)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                # Handle Rate Limiting (429) & Transient Server Errors (500, 502, 503, 504)
                if resp.status_code in (429, 500, 502, 503, 504):
                    retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                    print(f"    [WARN] HTTP {resp.status_code} on {endpoint}. Retrying in {retry_after}s (Attempt {attempt}/{max_retries})...")
                    time.sleep(retry_after)
                    continue

                if resp.status_code >= 400:
                    print(f"    [ERROR] HTTP {resp.status_code} on {endpoint}: {resp.text}")
                    return None

                return resp.json() if resp.text else {}

            except requests.exceptions.RequestException as exc:
                wait_time = 2 ** attempt
                print(f"    [WARN] Connection error: {exc}. Retrying in {wait_time}s (Attempt {attempt}/{max_retries})...")
                time.sleep(wait_time)

        print(f"    [ERROR] Exceeded max retries for {endpoint}")
        return None

    def get_all_configurations(self):
        """Fetches all AppSec configurations for the account."""
        endpoint = "/appsec/v1/configs"
        data = self.api_request("GET", endpoint)
        if not data:
            return []
        return data.get("configurations", [])

    def ensure_editable_version(self, config_id, latest_version, prod_version, staging_version):
        """Creates a new draft version if the latest version is already active/locked."""
        if not self.create_version:
            return latest_version

        if latest_version in (prod_version, staging_version):
            print(f"  [INFO] Latest version ({latest_version}) is active. Creating new version for Config {config_id}...")
            endpoint = f"/appsec/v1/configs/{config_id}/versions"
            payload = {"createFromVersion": latest_version}
            res = self.api_request("POST", endpoint, payload=payload)
            if res and "version" in res:
                new_ver = res["version"]
                print(f"  [SUCCESS] Created new editable version: {new_ver}")
                return new_ver
            else:
                print(f"  [WARN] Failed to create new version, falling back to version {latest_version}")
        return latest_version

    def get_security_policies(self, config_id, version):
        """Fetches all security policies for a specific configuration version."""
        endpoint = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies"
        data = self.api_request("GET", endpoint)
        if not data:
            return []
        return data.get("policies", [])

    def get_rapid_rules(self, config_id, version, policy_id):
        """Fetches all rapid rules assigned to a security policy."""
        endpoint = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules"
        data = self.api_request("GET", endpoint)
        if not data:
            return []
        return data.get("rapidRules", [])

    def update_rule_action(self, config_id, version, policy_id, rule_id, rule_version, action="deny"):
        """Updates the specified rapid rule action."""
        endpoint = (
            f"/appsec/v1/configs/{config_id}/versions/{version}/"
            f"security-policies/{policy_id}/rapid-rules/{rule_id}/"
            f"versions/{rule_version}/action"
        )
        payload = {"action": action}
        return self.api_request("PUT", endpoint, payload=payload)

    def set_rule_lock(self, config_id, version, policy_id, rule_id, lock=True):
        """Locks or unlocks the rapid rule action across future rule versions."""
        endpoint = (
            f"/appsec/v1/configs/{config_id}/versions/{version}/"
            f"security-policies/{policy_id}/rapid-rules/{rule_id}/lock"
        )
        payload = {"lock": lock}
        return self.api_request("PUT", endpoint, payload=payload)

    def run(self, target_rule_id=None, target_config_id=None):
        """Main execution loop traversing configs, policies, and rapid rules."""
        print("=" * 70)
        print("Akamai Rapid Rules Global Update")
        if self.account_id:
            print(f"Account Switch Key : {self.account_id}")
        print(f"Target Rule ID     : {target_rule_id if target_rule_id else 'ALL rapid rules'}")
        print(f"Target Action      : deny")
        print(f"Lock Action        : {'YES' if self.lock_action else 'NO (Version-specific)'}")
        print("=" * 70)

        configs = self.get_all_configurations()
        if not configs:
            print("[INFO] No configurations found or unable to access account.")
            return

        print(f"Discovered {len(configs)} security configuration(s).\n")

        total_policies_scanned = 0
        total_rules_updated = 0
        total_rules_skipped = 0
        total_rules_locked = 0

        for cfg in configs:
            cfg_id = cfg.get("id")
            cfg_name = cfg.get("name", "Unnamed")
            latest_ver = cfg.get("latestVersion")
            prod_ver = cfg.get("productionVersion")
            staging_ver = cfg.get("stagingVersion")

            if target_config_id and str(cfg_id) != str(target_config_id):
                continue

            print(f"--> Config: '{cfg_name}' (ID: {cfg_id})")

            target_ver = self.ensure_editable_version(cfg_id, latest_ver, prod_ver, staging_ver)

            policies = self.get_security_policies(cfg_id, target_ver)
            if not policies:
                print(f"    No security policies found for version {target_ver}.")
                continue

            print(f"    Found {len(policies)} policy/policies in version {target_ver}.")

            for pol in policies:
                pol_id = pol.get("policyId")
                pol_name = pol.get("policyName", pol_id)
                total_policies_scanned += 1

                rapid_rules = self.get_rapid_rules(cfg_id, target_ver, pol_id)
                if not rapid_rules:
                    continue

                for r in rapid_rules:
                    r_id = r.get("id")
                    r_ver = r.get("version")
                    curr_action = r.get("action")
                    is_locked = r.get("lock", False)

                    # Filter by rule ID if specified
                    if target_rule_id and str(r_id) != str(target_rule_id):
                        continue

                    if curr_action == "deny":
                        print(f"      [SKIP] Policy '{pol_name}' - Rule {r_id} is already set to 'deny'.")
                        total_rules_skipped += 1
                    else:
                        print(f"      [UPDATE] Policy '{pol_name}' - Updating Rule {r_id} (v{r_ver}) from '{curr_action}' to 'deny'...")
                        result = self.update_rule_action(cfg_id, target_ver, pol_id, r_id, r_ver, action="deny")
                        if result is not None:
                            print(f"      [SUCCESS] Rule {r_id} updated to 'deny'.")
                            total_rules_updated += 1
                        else:
                            print(f"      [FAILED] Rule {r_id} could not be updated.")

                    # Apply lock if requested
                    if self.lock_action and r_id:
                        if is_locked:
                            print(f"      [LOCK] Policy '{pol_name}' - Rule {r_id} is already locked.")
                        else:
                            print(f"      [LOCK] Policy '{pol_name}' - Locking Rule {r_id} action...")
                            lock_res = self.set_rule_lock(cfg_id, target_ver, pol_id, r_id, lock=True)
                            if lock_res is not None:
                                print(f"      [SUCCESS] Rule {r_id} locked successfully.")
                                total_rules_locked += 1
                            else:
                                print(f"      [FAILED] Rule {r_id} lock failed.")

        print("\n" + "=" * 70)
        print("Summary:")
        print(f"  Total Policies Scanned : {total_policies_scanned}")
        print(f"  Rules Updated to Deny  : {total_rules_updated}")
        print(f"  Rules Already Deny     : {total_rules_skipped}")
        if self.lock_action:
            print(f"  Rules Newly Locked     : {total_rules_locked}")
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Automatically update Rapid Rules across all security policies in an Akamai account."
    )
    parser.add_argument(
        "--account-id",
        required=True,
        help="Akamai Account Switch Key (Account ID) for cross-account operations."
    )
    parser.add_argument(
        "--rule-id",
        required=False,
        help="Optional: Specific Rapid Rule ID to update (e.g. 1000001). If omitted, all rapid rules are updated."
    )
    parser.add_argument(
        "--config-id",
        required=False,
        help="Optional: Limit updates to a single security configuration ID."
    )
    parser.add_argument(
        "--create-new-version",
        action="store_true",
        help="Automatically create a new editable version if the latest version is already active in Staging/Prod."
    )
    parser.add_argument(
        "--lock",
        action="store_true",
        help="Lock the rule action so it automatically applies to all new versions released by Akamai."
    )
    parser.add_argument(
        "--edgerc",
        default="~/.edgerc",
        help="Path to .edgerc authentication credentials (default: ~/.edgerc)."
    )
    parser.add_argument(
        "--section",
        default="default",
        help="Section name inside .edgerc (default: default)."
    )

    args = parser.parse_args()

    updater = AkamaiRapidRulesUpdater(
        edgerc_path=args.edgerc,
        section=args.section,
        account_id=args.account_id,
        create_version=args.create_new_version,
        lock_action=args.lock
    )
    updater.run(target_rule_id=args.rule_id, target_config_id=args.config_id)


if __name__ == "__main__":
    main()