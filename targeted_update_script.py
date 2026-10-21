#!/usr/bin/env python3
import requests
import time
import argparse
import os
import sys

try:
    from akamai.edgegrid import EdgeGridAuth, EdgeRc
except ImportError:
    print("Error: Required library 'edgegrid-python' is not installed.")
    print("Please install it using: pip install edgegrid-python")
    sys.exit(1)

def update_rapid_rules(config_id, version, policy_id, account_id, edgerc_path, section, target_rule_id=None, lock_action=False):
    # Initialize EdgeGrid Authentication
    try:
        edgerc = EdgeRc(edgerc_path)
        baseurl = 'https://%s' % edgerc.get(section, 'host')
        s = requests.Session()
        s.auth = EdgeGridAuth.from_edgerc(edgerc, section)
    except Exception as e:
        print(f"Error authenticating. Ensure your .edgerc is set up correctly: {e}")
        return

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Helper function to handle requests and retries
    def make_request(method, endpoint, payload=None):
        url = f"{baseurl}{endpoint}"
        params = {}
        if account_id:
            params['accountSwitchKey'] = account_id

        max_retries = 5
        for attempt in range(max_retries):
            try:
                if method == 'GET':
                    response = s.get(url, headers=headers, params=params)
                elif method == 'PUT':
                    response = s.put(url, headers=headers, params=params, json=payload)
                else:
                    return None

                # Handle Rate Limiting and Server Errors
                if response.status_code in [429, 500, 502, 503, 504]:
                    retry_after = int(response.headers.get('Retry-After', 5))
                    print(f"Received error {response.status_code}. Retrying in {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                return response.json() if response.text else {}
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt+1} failed: {e}")
                time.sleep(5)
        print(f"Failed to complete request to {endpoint} after {max_retries} retries.")
        return None

    # Step 1: Fetch all Rapid Rules
    print(f"Fetching rapid rules for Policy: {policy_id} (Config: {config_id}, Version: {version})...")
    get_url = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules"
    
    rules_data = make_request('GET', get_url)
    if not rules_data or 'rapidRules' not in rules_data:
        print("No rapid rules found or failed to fetch.")
        return

    rapid_rules = rules_data['rapidRules']
    print(f"Found {len(rapid_rules)} rapid rules.")

    # Step 2: Loop through and update rule(s) to 'deny' and optionally lock
    success_count = 0
    skipped_count = 0
    matched_rules = 0

    for rule in rapid_rules:
        rule_id = rule.get('id')
        rule_version = rule.get('version')
        current_action = rule.get('action')
        is_locked = rule.get('lock', False)
        
        # If a specific rule ID was provided, skip non-matching rules
        if target_rule_id and str(rule_id) != str(target_rule_id):
            continue
            
        matched_rules += 1

        action_updated = False
        if current_action == 'deny':
            print(f"Rule ID {rule_id} is already set to 'deny'.")
            skipped_count += 1
        else:
            if rule_id and rule_version:
                print(f"Updating Rule ID {rule_id} (Version {rule_version}) to 'deny'...")
                put_url = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules/{rule_id}/versions/{rule_version}/action"
                payload = {"action": "deny"}
                result = make_request('PUT', put_url, payload)
                if result is not None:
                    print(f"Successfully updated Rule ID {rule_id} action.")
                    success_count += 1
                    action_updated = True
                else:
                    print(f"Failed to update Rule ID {rule_id} action.")

        # Locking the rule action if requested
        if lock_action and rule_id:
            if is_locked:
                print(f"Rule ID {rule_id} is already locked.")
            else:
                print(f"Locking Rule ID {rule_id} action...")
                lock_url = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies/{policy_id}/rapid-rules/{rule_id}/lock"
                lock_payload = {"lock": True}
                lock_result = make_request('PUT', lock_url, lock_payload)
                if lock_result is not None:
                    print(f"Successfully locked Rule ID {rule_id}.")
                else:
                    print(f"Failed to lock Rule ID {rule_id}.")
                
    print(f"\nExecution complete.")
    if target_rule_id and matched_rules == 0:
        print(f"Warning: Target Rule ID {target_rule_id} was not found in this policy.")
    else:
        print(f"Updated Actions: {success_count} | Skipped (already deny): {skipped_count} | Matched: {matched_rules}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update Akamai Managed Rapid Rules to Deny for a specific policy")
    parser.add_argument("--config-id", required=True, help="Security Configuration ID")
    parser.add_argument("--version", required=True, help="Configuration Version Number")
    parser.add_argument("--policy-id", required=True, help="Security Policy ID")
    parser.add_argument("--account-id", required=False, help="Account ID (Account Switch Key) to allow cross-account operations")
    parser.add_argument("--rule-id", required=False, help="Optional: Specific Rapid Rule ID to update (e.g. 1000001). If omitted, updates all rules in the policy.")
    parser.add_argument("--lock", action="store_true", help="Lock the rule action so it automatically applies to all new versions released by Akamai.")
    parser.add_argument("--edgerc", default="~/.edgerc", help="Path to .edgerc file (default: ~/.edgerc)")
    parser.add_argument("--section", default="default", help="Section in .edgerc file (default: default)")
    
    args = parser.parse_args()
    edgerc_path = os.path.expanduser(args.edgerc)
    
    update_rapid_rules(args.config_id, args.version, args.policy_id, args.account_id, edgerc_path, args.section, args.rule_id, args.lock)