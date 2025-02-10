import argparse
import json
import os

def save_results(test_result):
    """Save test results to security_report.json without duplicates."""
    filename = "security_report.json"

    # Load existing report if available
    if os.path.exists(filename):
        with open(filename, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Avoid duplicate entries
    for entry in data:
        if entry["type"] == test_result["type"]:
            entry["results"] = test_result["results"]
            break
    else:
        data.append(test_result)

    # Save updated report
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def run_test(url, test_type, param):
    """Simulate security testing based on test type."""
    test_payloads = {
        "sql": [["' OR '1'='1", False], ["'; DROP TABLE users --", False]],
        "xss": [["<script>alert('XSS')</script>", False], ["<img src='x' onerror='alert(1)'>", False]],
        "rce": [[";ls", False], ["& whoami", False]]
    }

    results = test_payloads.get(test_type, [])

    test_result = {
        "type": "SQL Injection" if test_type == "sql" else test_type.upper(),
        "results": results
    }

    save_results(test_result)

    # Print results directly
    print(f"\n🔍 Security Test: {test_result['type']}")
    for payload, detected in test_result["results"]:
        print(f" - Payload: {payload} | Vulnerable: {detected}")
    print("\n✅ Report saved to security_report.json\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Testing Framework")
    parser.add_argument("--url", required=True, help="Target URL for testing")
    parser.add_argument("--test", choices=["sql", "xss", "rce"], required=True, help="Type of test to perform")
    parser.add_argument("--param", required=True, help="Parameter to test")

    args = parser.parse_args()

    run_test(args.url, args.test, args.param)
