# Akamai Rapid Rules Audit Tool

An enterprise-grade, multi-account audit and discovery tool for **Akamai App & API Protector** and **Kona Site Defender**. This tool identifies security policies where **Rapid Rules** are customer-managed (explicitly customized or locked) rather than delegated to Akamai's automated threat research intelligence.

The output report automatically embeds the **Account Switch Key** and the **exact execution date & timestamp** in the CSV filename.

---

## 1. Overview & Use Case

Akamai Rapid Rules provide rapid zero-day protection against critical vulnerabilities (CVEs) before they are incorporated into the primary Adaptive Security Engine (ASE) or Kona Rule Set (KRS).

### Governance Models
1. **Akamai-Managed (Default / Recommended):**
   * The policy default action is `akamai_managed`.
   * Individual rules dynamically inherit this setting (`lock: false`).
   * Akamai Threat Research decides in real-time whether a rule alerts or denies based on global threat signals and false-positive telemetry.
   * **Note:** Purely Akamai-managed policies are **strictly excluded** from this audit report.
2. **Customer-Managed (Audited by this tool):**
   * **Policy-Level Override:** The policy default action is explicitly set by the customer to a fixed action (`alert`, `deny`, `none`, or `deny_custom_...`).
   * **Individual Rule Lock:** An administrator has explicitly locked a rule (`lock: true`) to freeze its action across future version updates, even if the policy default is `akamai_managed`.

### Key Capabilities of This Tool
* **Mandatory Account Scope:** Enforces explicit account selection via CLI flags (`-a` or `--all`).
* **Strict Customer-Managed Filtering:** Completely eliminates false positives for `akamai_managed` policies where no rules are locked.
* **Multi-Account & Universal Discovery:** Runs against a single account, multiple specified accounts, or automatically crawls **all** accessible accounts under an enterprise contract via IAM API.
* **Account & Timestamped Output Filename:** Automatically names the output CSV report based on the audited account and execution datetime (e.g., `customer_managed_rapid_rules_1-1DJL_20261021_144500.csv`).
* **Fault-Tolerant Engine:** Gracefully handles non-WAF policies (HTTP 400), uninitialized legacy configurations (HTTP 500), and rate-limiting throttling (HTTP 429) without crashing.
* **Real-Time Disk Flushing:** Writes findings directly to disk after each discovery, allowing operators to inspect and monitor the CSV output while the script is running.

---

## 2. macOS Terminal Setup (From Scratch)

Follow these steps to set up your environment in macOS Terminal:

### Step 2.1: Open Terminal
Press `Command (⌘) + Space`, type `Terminal`, and press `Enter`.

### Step 2.2: Verify Python 3
macOS includes Python 3. Verify its presence:
```bash
python3 --version
```
*(If prompted to install Developer Tools, click **Install** and allow it to finish).*

### Step 2.3: Create Workspace & Virtual Environment
Isolate project dependencies by creating a dedicated virtual environment:
```bash
mkdir -p ~/akamai-audit
cd ~/akamai-audit
python3 -m venv venv
source venv/bin/activate
```
*(Your prompt will now show `(venv)` to indicate the virtual environment is active).*

### Step 2.4: Install Required Packages
Install the official Akamai EdgeGrid authentication library and `requests`:
```bash
pip install --upgrade pip
pip install requests edgegrid-python
```

---

## 3. Akamai Credentials Setup (`~/.edgerc`)

The script authenticates using Akamai EdgeGrid tokens stored in `~/.edgerc`.

1. Open or create the file:
   ```bash
   nano ~/.edgerc
   ```
2. Paste your Akamai API tokens:
   ```ini
   [default]
   client_secret = YOUR_CLIENT_SECRET
   host = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net
   access_token = YOUR_ACCESS_TOKEN
   client_token = YOUR_CLIENT_TOKEN
   ```
   *(To save in `nano`, press `Control + O`, then `Enter`. To exit, press `Control + X`).*

3. Restrict permissions so only your user account can read the secrets:
   ```bash
   chmod 600 ~/.edgerc
   ```

> **API Permission Requirements:**
> * **Application Security (`/appsec/v1`):** Minimum **READ** access (to audit configs, versions, policies, and rapid rules).
> * **Identity and Access Management (`/identity-management/v3`):** Required only when using the `--all` flag to discover all accessible accounts.

---

## 4. Command-Line Flags Reference

| Flag | Long Flag | Required? | Description |
| :--- | :--- | :---: | :--- |
| `-a` | `--account` | **Yes\*** | Account Switch Key(s). Can be comma-separated or supplied multiple times. |
| | `--all` | **Yes\*** | Queries IAM API to discover and audit **every** account accessible to the API client. |
| | `--custom-defaults-only` | No | Filters strictly for policies where `defaultAction` is custom (`alert`, `deny`, etc.), skipping policies where the default is `akamai_managed` even if individual rules are locked. |
| `-o` | `--output` | No | Custom override for the output CSV filename. |
| `-e` | `--edgerc` | No | Path to `.edgerc` file (Default: `~/.edgerc`). |
| `-s` | `--section` | No | Section header in `.edgerc` (Default: `default`). |
| `-h` | `--help` | No | Displays the help menu and sample commands. |

*\* Note: You must provide either `--account` (`-a`) OR `--all`.*

---

## 5. Sample Commands & Automatic File Naming

### 5.1. Single Account Audit
Audit a specific account (e.g., Morgan Stanley `1-1DJL`):
```bash
python audit_rapid_rules_multi_account_v2.py -a "1-1DJL"
```
* **Auto-generated filename:**  
  `customer_managed_rapid_rules_1-1DJL_YYYYMMDD_HHMMSS.csv`

### 5.2. Multiple Specific Accounts
Audit a selected group of accounts in a single execution:

**Using Comma-Separated Values:**
```bash
python audit_rapid_rules_multi_account_v2.py -a "1-1DJL,1-2ABC,1-3XYZ"
```

**Using Multiple `-a` Flags:**
```bash
python audit_rapid_rules_multi_account_v2.py -a "1-1DJL" -a "1-2ABC" -a "1-3XYZ"
```
* **Auto-generated filename:**  
  `customer_managed_rapid_rules_1-1DJL_1-2ABC_1-3XYZ_YYYYMMDD_HHMMSS.csv`  
  *(If more than 3 accounts are specified: `customer_managed_rapid_rules_multi_account_YYYYMMDD_HHMMSS.csv`)*

### 5.3. All Accessible Accounts
Automatically discover every sub-account across your enterprise tenant and audit them sequentially:
```bash
python audit_rapid_rules_multi_account_v2.py --all
```
* **Auto-generated filename:**  
  `customer_managed_rapid_rules_ALL_ACCOUNTS_YYYYMMDD_HHMMSS.csv`

### 5.4. Filter Strictly by Custom Default Action Only
Ignore policies that have an `akamai_managed` default even if individual rules are locked:
```bash
python audit_rapid_rules_multi_account_v2.py -a "1-1DJL" --custom-defaults-only
```

---

## 6. How to Read and Monitor the Output

### Real-Time Live Monitoring
The script flushes each finding to disk immediately. You do not need to wait for the scan to finish to inspect the output.

In a separate Terminal tab (`Command + T`):
```bash
cd ~/akamai-audit
tail -f customer_managed_rapid_rules_*.csv
```

### Opening the Report
* **Open in Microsoft Excel or Apple Numbers:**
  ```bash
  open customer_managed_rapid_rules_*.csv
  ```
* **View formatted directly in Terminal:**
  ```bash
  column -s, -t < customer_managed_rapid_rules_*.csv | less -#2 -N -S
  ```

### CSV Schema Definition
| Column Header | Description | Example |
| :--- | :--- | :--- |
| `account_switch_key` | Target Akamai Account Identifier. | `1-1DJL` |
| `account_name` | Name of the account as registered in Akamai IAM. | `Morgan Stanley - Prod` |
| `config_id` | Unique ID of the Security Configuration. | `12345` |
| `config_name` | Display name of the Security Configuration. | `Enterprise_Public_WAF` |
| `environment` | Active environment evaluated (`PROD`, `STAGING`, or `DRAFT`). | `PROD` |
| `version` | Version number evaluated. | `4` |
| `policy_id` | Identifier for the security policy. | `POL_98765` |
| `policy_name` | Friendly name of the security policy. | `API_Gateway_Policy` |
| `management_type` | Category of customer control (`CUSTOMER_MANAGED_POLICY_DEFAULT` or `CUSTOMER_LOCKED_RULES_ONLY`). | `CUSTOMER_MANAGED_POLICY_DEFAULT` |
| `default_action` | Base action for Rapid Rules in this policy. | `alert`, `deny`, or `none` |
| `custom_rule_count`| Total count of rules explicitly locked by an administrator. | `2` |
| `rule_details` | Semicolon-delimited list of rule IDs, actions, and lock statuses. | `ID:3000971(act:deny,locked:True)` |

---

## 7. Troubleshooting & Error Reference

### 1. HTTP 400: `"Application layer control isn't enabled for policy"`
* **Cause:** The policy is used solely for non-WAF controls (e.g., Rate Limiting, IP/Geo firewalls, or Bot Management), so the Rapid Rules submodule is deactivated.
* **Resolution in Script:** Automatically identified and labeled as `WAF_DISABLED`. The script cleanly skips this policy without crashing or attempting redundant rule queries.

### 2. HTTP 500: `"INTERNAL-SERVER-ERROR"` (detail: `"Error occurred while processing the request"`)
* **Cause:** Occurs on legacy policies (often migrated from KRS) where the Rapid Rules schema was never initialized in the backend database.
* **Resolution in Script:** Automatically caught and logged in the CSV report as `HTTP_500_BACKEND_ERROR` under `default_action`, allowing operators to review the specific policy in Control Center.

### 3. HTTP 429: `"Too Many Requests"`
* **Cause:** API client rate limits reached when scanning large accounts with hundreds of policies.
* **Resolution in Script:** Built-in exponential backoff automatically pauses for 2s, 4s, and 8s, then retries the request seamlessly.

### 4. HTTP 403: `"Forbidden"` or `"Unauthorized Client"`
* **Cause:** The API credentials lack permission for `/appsec/v1` or the specific `accountSwitchKey`.
* **Resolution:** In Akamai Control Center, navigate to **Identity & Access Management** > find your API Client > ensure it is granted **READ** access to **Application Security** and that the account switch key is listed in its authorized accounts.

### 5. HTTP 401: `"Timestamp difference too large"`
* **Cause:** Your macOS system clock has drifted by more than 30 seconds from NTP time.
* **Resolution:** Go to macOS **System Settings** > **General** > **Date & Time** > toggle "Set time and date automatically" off and on.

### 6. `--all` Fails with: `"Failed to retrieve accessible accounts via IAM API"`
* **Cause:** The API client has permission for Application Security, but lacks permission for the Identity & Access Management (IAM) API.
* **Resolution:** Add **Identity & Access Management (Read)** to the API Client's service permissions in Control Center, or use `-a` to pass account IDs explicitly.
