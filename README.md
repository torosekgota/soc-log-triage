# SOC Log Triage & Phishing Analyzer Toolkit

A lightweight, Python-based Command Line Interface (CLI) designed for SOC Tier-1 analysts. This toolkit automates the initial triage of Linux authentication logs, performs heuristic analysis on suspicious URLs, and monitors file integrity.

All log detections are mapped to **ISO/IEC 27001:2022** controls to align technical operations with compliance requirements.

## 🛠️ Features

### 1. Log Triage (`triage`)

Parses standard Linux `auth.log` files and runs three practical detection rules:

- **Brute Force Followed by Compromise:** >5 failed logins within 60 seconds followed by a successful login from the same IP.
- **Impossible Travel:** Successful logins for the same user from two different IPs within 5 minutes.
- **Password Spray:** 1 failed login attempt across 5+ distinct usernames from a single IP within 2 minutes.

### 2. Phishing URL Analyzer (`analyze-url`)

Analyzes suspicious links **without executing or visiting them**. It uses rule-based heuristics to generate a risk score (0-100):

- Detects raw IP addresses used instead of domain names.
- Flags known URL shorteners (e.g., `bit.ly`, `tinyurl.com`).
- Detects potential brand impersonation (e.g., `paypal-security-update.com`).
- Calculates Shannon entropy to flag randomly generated domains.

### 3. File Integrity Monitor (`fim`)

Detects unauthorized changes to critical system files using SHA-256 hashing.

- **Baseline:** Scans a directory and saves a JSON snapshot of file hashes.
- **Audit:** Compares the current directory state against the baseline to flag created, modified, or deleted files.
- Maps to **ISO 27001 Control A.8.9 (Configuration Management)**.

## 🚀 Installation & Usage

1. **Clone the repository:**
    ```bash
    git clone https://github.com/torosekgota/soc-log-triage.git
    cd soc-log-triage
    ```
