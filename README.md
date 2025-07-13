# SMTP-Hunter

**SMTP-Hunter** is an advanced, aggressive SMTP penetration testing tool designed for security professionals to identify vulnerabilities in SMTP servers. It supports comprehensive enumeration, fuzzing, brute-forcing, and modern protocol compliance checks, with AI-driven anomaly detection and detailed reporting. This tool is built for the 2025 threat landscape, incorporating checks for recent CVEs, SMTP smuggling, and cloud-hosted SMTP services.

**WARNING: SMTP-Hunter performs aggressive penetration testing. Use ONLY on systems you are legally authorized to test with explicit, written permission. Unauthorized use is illegal and can lead to severe consequences, including legal action.**

## Features

- **Banner Grabbing & ESMTP Discovery**: Captures server banners and enumerates ESMTP extensions (e.g., STARTTLS, AUTH).
- **User Enumeration**: Uses VRFY, EXPN, and RCPT TO methods with timing analysis to identify valid users.
- **Open Relay Testing**: Aggressively tests for open relay vulnerabilities with dynamic sender/recipient combinations.
- **SMTP Command Injection & Fuzzing**: Tests for command injection and smuggling vulnerabilities using raw socket fuzzing.
- **Brute Force Attacks**: Concurrent brute-forcing with adaptive delays and lockout detection.
- **Modern Protocol Checks**: Validates MTA-STS and DANE compliance for secure email delivery.
- **Cloud/SaaS Detection**: Identifies if the SMTP server is hosted on AWS SES, Azure, Google Cloud, SendGrid, etc.
- **CVE Matching**: Matches server banners and features against a database of known SMTP vulnerabilities (2024-2025).
- **AI Anomaly Detection**: Uses machine learning (Isolation Forest) to detect anomalous server responses and adjust attack pacing.
- **Comprehensive Reporting**: Generates detailed HTML reports with visualizations (requires matplotlib).
- **Proxy Support**: Supports SOCKS5 and HTTP proxies for anonymized testing.
- **Nmap Integration**: Runs targeted Nmap scripts for additional reconnaissance.

## Prerequisites

To run SMTP-Hunter, ensure the following are installed:

- **Python 3.8+** (tested with Python 3.10)
- **Required Python Libraries**:
  ```bash
  pip install numpy scikit-learn matplotlib dnspython requests pysocks
  ```
  - `numpy`, `scikit-learn`: For AI-driven anomaly detection.
  - `matplotlib`: For timing analysis visualizations.
  - `dnspython`, `requests`: For MTA-STS and DANE checks.
  - `pysocks`: For SOCKS proxy support.
- **Nmap** (optional, for `--nmap` flag): Install Nmap and ensure it's in your PATH.
  ```bash
  sudo apt-get install nmap  # Debian/Ubuntu
  sudo dnf install nmap      # Fedora
  brew install nmap          # macOS
  ```
- **Permissions**: Written authorization to test the target system.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/exfil0/SMTP-Hunter.git
   cd SMTP-Hunter
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   If `requirements.txt` is not provided, manually install the libraries listed above.

3. Verify Nmap installation (if using `--nmap`):
   ```bash
   nmap --version
   ```

## Usage

SMTP-Hunter is a command-line tool with flexible arguments for targeted testing. Below are step-by-step instructions for using its features.

### Basic Command Structure

```bash
python smtp_hunter.py <target> [options]
```

- `<target>`: The SMTP server IP or hostname (e.g., `mail.example.com` or `192.168.1.10`).

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--port <port>` | SMTP port (25 for SMTP, 465 for SMTPS, 587 for Submission) | 25 |
| `--users_file <file>` | File with usernames (one per line) | Built-in default list |
| `--passwords_file <file>` | File with passwords (one per line) | Built-in default list |
| `--from_email <emails>` | Comma-separated FROM emails for open relay/RCPT tests | `attacker@example.com,<target-derived>` |
| `--to_email <emails>` | Comma-separated TO emails for open relay tests | `external.recipient@evilexample.com` |
| `--expn_lists <lists>` | Comma-separated mailing list names for EXPN | `staff,admin,support,postmaster,noreply,info` |
| `--domains <domains>` | Comma-separated domains for RCPT TO enumeration | Target hostname |
| `--tls` | Force TLS/STARTTLS where possible | Disabled |
| `--nmap` | Run Nmap SMTP scripts (requires Nmap) | Disabled |
| `--workers <num>` | Concurrent workers for brute force | 10 |
| `--fast` | Use aggressive, low-delay settings (less stealthy) | Disabled |
| `--no_ai` | Disable AI anomaly detection | Enabled if `scikit-learn` installed |
| `--no_plot` | Disable timing graph generation | Enabled if `matplotlib` installed |
| `--proxy <proxy>` | Proxy (e.g., `socks5://127.0.0.1:9050` or `http://127.0.0.1:8080`) | None |

### Example Commands

1. **Basic Scan (Banner, STARTTLS, Basic Enumeration)**:
   ```bash
   python smtp_hunter.py mail.example.com --port 25
   ```
   Performs banner grabbing, STARTTLS/extension checks, and basic user enumeration with default lists.

2. **Aggressive Scan with User Enumeration**:
   ```bash
   python smtp_hunter.py mail.example.com --port 587 --users_file users.txt --domains example.com,internal.example.com --tls
   ```
   Enumerates users using VRFY, EXPN, and RCPT TO with timing analysis, forcing TLS.

3. **Brute Force Attack**:
   ```bash
   python smtp_hunter.py mail.example.com --port 465 --users_file users.txt --passwords_file passwords.txt --workers 20 --tls
   ```
   Performs concurrent brute-forcing with 20 workers, using TLS on port 465.

4. **Open Relay and Fuzzing Test**:
   ```bash
   python smtp_hunter.py mail.example.com --from_email attacker@example.com,user@example.com --to_email victim@external.com --fast
   ```
   Tests for open relays and performs command injection/fuzzing with aggressive delays.

5. **Full Scan with Nmap, Proxy, and All Features**:
   ```bash
   python smtp_hunter.py mail.example.com --port 25 --users_file users.txt --passwords_file passwords.txt --domains example.com --nmap --proxy socks5://127.0.0.1:9050
   ```
   Runs a comprehensive test including Nmap, proxy routing, and all enumeration/fuzzing features.

### Input File Formats

- **users.txt** (one username per line):
  ```
  admin
  test
  postmaster
  user1
  ```

- **passwords.txt** (one password per line):
  ```
  password123
  admin2025
  test!@#
  ```

### Output

- **Console Output**: Real-time progress with findings (e.g., valid users, open relay status).
- **Log File**: Detailed logs saved to `smtp_pentest.log`.
- **HTML Report**: Comprehensive report saved as `smtp_pentest_report_<target>_<timestamp>.html`.
- **Timing Graphs** (if `matplotlib` installed): PNG files (`rcpt_timing.png`, `bruteforce_timing.png`) with response time analysis.

### Step-by-Step Usage Guide

1. **Prepare Input Files**:
   - Create `users.txt` and `passwords.txt` with target-specific usernames and passwords.
   - Optionally, define custom `from_email`, `to_email`, and `domains` for open relay and enumeration.

2. **Verify Dependencies**:
   ```bash
   pip show numpy scikit-learn matplotlib dnspython requests pysocks
   nmap --version
   ```

3. **Run a Basic Scan**:
   ```bash
   python smtp_hunter.py mail.example.com
   ```
   This performs initial reconnaissance (banner, STARTTLS, extensions) and basic enumeration.

4. **Perform User Enumeration**:
   ```bash
   python smtp_hunter.py mail.example.com --users_file users.txt --domains example.com
   ```
   Tests VRFY, EXPN, and RCPT TO for user enumeration with timing analysis.

5. **Test for Open Relay and Fuzzing**:
   ```bash
   python smtp_hunter.py mail.example.com --from_email attacker@example.com --to_email victim@external.com
   ```
   Checks for open relay vulnerabilities and performs command injection/smuggling tests.

6. **Brute Force Authentication**:
   ```bash
   python smtp_hunter.py mail.example.com --port 587 --users_file users.txt --passwords_file passwords.txt --tls --workers 15
   ```
   Attempts to brute-force credentials with TLS and 15 concurrent workers.

7. **Enable Nmap and Proxy**:
   ```bash
   python smtp_hunter.py mail.example.com --nmap --proxy socks5://127.0.0.1:9050
   ```
   Runs Nmap scripts and routes traffic through a SOCKS5 proxy.

8. **Review Results**:
   - Check `smtp_pentest.log` for detailed logs.
   - Open the generated HTML report in a browser for a comprehensive summary.
   - View `rcpt_timing.png` and `bruteforce_timing.png` for timing analysis (if enabled).

## Advanced Features

- **AI Anomaly Detection**:
  - Requires `scikit-learn` and `numpy`.
  - Uses an Isolation Forest model to detect anomalous response times/codes, dynamically adjusting attack delays to evade detection.
  - Disable with `--no_ai` if not needed or if dependencies are missing.

- **Timing Analysis**:
  - Requires `matplotlib`.
  - Generates box plots for RCPT TO and brute force response times to identify timing-based side channels.
  - Disable with `--no_plot`.

- **Proxy Support**:
  - Requires `pysocks` for SOCKS5 or HTTP proxies.
  - Example: `--proxy socks5://127.0.0.1:9050` routes all traffic through Tor or another proxy.

- **CVE Database**:
  - Matches server banners and features against known vulnerabilities (e.g., CVE-2025-26794, CVE-2024-27305).
  - Includes general weaknesses like VRFY/EXPN exposure and open relays.

## Security and Legal Considerations

- **Authorized Use Only**: Ensure you have explicit, written permission to test the target system. Unauthorized use violates laws like the CFAA (USA) or Computer Misuse Act (UK).
- **Responsible Disclosure**: Report findings to the system owner promptly and securely.
- **Data Handling**: The HTML report and log file contain sensitive information. Store and transmit them securely.

## Example Output

**Console Output**:
```
===== Starting AGGRESSIVE SMTP Penetration Test - 2025 Edition for: mail.example.com:25 =====

===== Step 0.1: Banner Grabbing =====
[+] Banner [mail.example.com:25]: 220 mail.example.com ESMTP Postfix

===== Step 0.2: ESMTP Capability Discovery (EHLO, STARTTLS) =====
[+] STARTTLS supported: True
[+] Supported ESMTP Extensions: STARTTLS, AUTH, PIPELINING

===== Step 2.1: User Enumeration (VRFY) =====
[+] Valid user (VRFY): admin@example.com (Response: 250 2.1.0 admin@example.com)
[-] Invalid user (VRFY): test@example.com (Response: 550 5.1.1 User unknown)

===== Step 3.1: Aggressive Open Relay Check =====
[!!!] Open Relay detected! Accepted attacker@example.com -> victim@external.com

===== Step 6: CVE Specific Findings =====
[+] Found 1 potential CVE/weakness matches.
- CVE: WEAKNESS-202X-OPEN-RELAY (Impact: Critical)

===== Generating Final Report =====
[+] Comprehensive HTML report generated: smtp_pentest_report_mail_example_com_1749234567.html
```

**HTML Report**:
- A polished, browser-viewable report with sections for executive summary, target information, enumeration findings, vulnerabilities, and recommendations.

## Troubleshooting

- **Connection Errors**:
  - Check if the target is reachable (`ping <target>` or `nc -zv <target> <port>`).
  - Verify proxy settings if using `--proxy`.
- **Missing Dependencies**:
  - Install missing libraries with `pip install <library>`.
  - Ensure Nmap is installed for `--nmap`.
- **Rate Limiting**:
  - If the server disconnects frequently, enable `--fast` for quicker scans or increase delays manually in the script.
- **AI/Plotting Issues**:
  - Disable with `--no_ai` or `--no_plot` if dependencies are unavailable.

## Contributing

Contributions are welcome! Please submit pull requests or issues to [github.com/exfil0/SMTP-Hunter](https://github.com/exfil0/SMTP-Hunter).

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

SMTP-Hunter is provided for educational and authorized security testing purposes only. The author (@exfil0) and contributors are not responsible for misuse or illegal activities. Always obtain explicit permission before testing any system.

---

**Author**: [exfil0](https://github.com/exfil0)  
**Version**: 1.0 (2025 Edition)  
**Contact**: Open an issue on GitHub for support or feature requests.
