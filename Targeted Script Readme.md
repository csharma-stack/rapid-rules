# Targeted Akamai Rapid Rules Update Script

This script is designed to surgically update Akamai Managed Rapid Rules to the `deny` action for a single, manually specified security policy.

## Prerequisites

1.  **Python 3.7+**
2.  **EdgeGrid Python Library**: Install via `pip install requests edgegrid-python`
3.  **Akamai API Credentials**: An active API client with **READ-WRITE** access to the Application Security API.

## Authentication Setup

Store your credentials in a `.edgerc` file in your home directory (`~/.edgerc`):

```ini
[default]
client_secret = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
host = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net
access_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
```

## Usage

This script requires you to explicitly declare the `config-id`, `version`, and `policy-id`.

**1. Update a single Rapid Rule and lock it (Recommended):**
```bash
python3 akamai_rapid_rules_targeted_deny.py \
  --config-id 12345 \
  --version 10 \
  --policy-id "sec_policy_1" \
  --account-id "B-C-1XYZ99" \
  --rule-id 1000001 \
  --lock
```

**2. Update all Rapid Rules in a policy:**
```bash
python3 akamai_rapid_rules_targeted_deny.py \
  --config-id 12345 \
  --version 10 \
  --policy-id "sec_policy_1" \
  --account-id "B-C-1XYZ99"
```

### Command Line Arguments

*   `--config-id` **(Required)**: Security Configuration ID.
*   `--version` **(Required)**: Configuration Version Number (Must be a draft/editable version).
*   `--policy-id` **(Required)**: Security Policy ID (e.g., `pol_12345`).
*   `--account-id` *(Optional)*: Account Switch Key (Account ID).
*   `--rule-id` *(Optional)*: Target a specific Rapid Rule ID (e.g., `1000001`). 
*   `--lock` *(Optional)*: Locks the rule action so future Akamai updates do not revert your `deny` setting.