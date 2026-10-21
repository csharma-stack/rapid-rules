# Akamai Rapid Rules Auditor

This script audits all Application Security (WAF) configurations across an Akamai account to identify **customer-managed** Rapid Rules. 

By default, Akamai Rapid Rules should be set to `akamai_managed`, allowing Akamai's Threat Research team to dynamically update and enforce rule actions. This script detects:
1. Policies where the default action is statically pinned (e.g., `alert` or `deny`).
2. Individual rules that are locked (`lock: true`) or have manual overrides.

Results are streamed in real-time to a CSV file for immediate analysis.

## Prerequisites

1. **Python 3.8+** installed on your system.
2. **Akamai API Credentials** with at least `READ` access to the Application Security (`appsec/v1`) API. 
3. The credentials must be placed in `~/.edgerc` under the `[default]` section.

## Setup Instructions

### 1. Set Up the EdgeGrid Credentials File
Create the `.edgerc` file in your home directory:

```bash
nano ~/.edgerc
```

Paste your Akamai API tokens:
```ini
[default]
client_secret = your_client_secret
host = akab-xxxx-xxxx.luna.akamaiapis.net
access_token = your_access_token
client_token = your_client_token
```

Secure the file (macOS/Linux):
```bash
chmod 600 ~/.edgerc
```

### 2. Create the Python Virtual Environment
Open your Terminal and run the following to create an isolated environment and install dependencies:

```bash
mkdir ~/akamai-audit
cd ~/akamai-audit

# Initialize and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Akamai libraries
pip install requests edgegrid-python
```

## How to Run for a Specific Account

Before executing, you must configure the script for the specific Akamai account you want to audit.

1. Open `audit_rapid_rules.py` in a text editor.
2. Locate the **CONFIGURATION SECTION** at the top of the file.
3. Update the `ACCOUNT_SWITCH_KEY` variable with your target Account ID (e.g., `"1-1DJL"` for Morgan Stanley, or `"F-AC-123456"`).
   * *Note: If you only have one account on your credentials, you can leave this as `""`.*

```python
# ==============================================================================
# CONFIGURATION SECTION
# ==============================================================================
ACCOUNT_SWITCH_KEY = "1-1DJL" 
```

4. Run the script:
```bash
python audit_rapid_rules.py
```

## Viewing the Live CSV Output

Because this script flushes data to the disk immediately, you can watch the CSV populate in real time while the script is running. 

Open a **new Terminal tab** (`Command + T`), navigate to the folder, and run:
```bash
cd ~/akamai-audit
tail -f rapid_rules_audit_1-1DJL.csv
```
*(Press `Control + C` to stop watching the live feed).*

When the script finishes, you can open the final report in Excel, Apple Numbers, or any text editor.
```bash
open rapid_rules_audit_1-1DJL.csv
```

## Error Failover Features

This script is built for large enterprise estates and will not crash during long runs:
* **HTTP 400 (WAF Disabled):** Cleanly skips policies used strictly for Botman or IP/Geo firewalling.
* **HTTP 500 (Legacy Policies):** Logs internal Akamai errors as `HTTP_500_BACKEND_ERROR` in the CSV and safely continues.
* **HTTP 429 (Rate Limits):** Employs exponential backoff and retry logic to respect Akamai's API gateways.