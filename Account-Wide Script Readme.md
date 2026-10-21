# Account-Wide Akamai Rapid Rules Update Script

This tool fully automates the discovery and updating of Akamai Managed Rapid Rules across your entire account hierarchy (Configurations -> Policies -> Rules). 

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

This script dynamically navigates the API. You only strictly need your `--account-id`.

**1. Global Sweep (Update a single rule everywhere and lock it):**
```bash
python3 akamai_bulk_rapid_rules_updater.py \
  --account-id "B-C-1XYZ99" \
  --rule-id 1000001 \
  --create-new-version \
  --lock
```

**2. Scope to a Single Configuration Tree:**
```bash
python3 akamai_bulk_rapid_rules_updater.py \
  --account-id "B-C-1XYZ99" \
  --config-id 12345 \
  --rule-id 1000001 \
  --create-new-version \
  --lock
```

### Command Line Arguments

*   `--account-id` **(Required)**: Akamai Account Switch Key (Account ID).
*   `--create-new-version` *(Optional)*: Highly recommended. Automatically drafts a new version if the current latest version is active in Staging or Production and locked.
*   `--rule-id` *(Optional)*: Specific Rapid Rule ID to target (e.g. `1000001`). If omitted, it will update *all* rapid rules.
*   `--lock` *(Optional)*: Locks the rule action so it automatically applies to all new versions released by Akamai.
*   `--config-id` *(Optional)*: Limit updates to a single security configuration ID instead of the entire account.