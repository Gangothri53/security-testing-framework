
# Security Testing Framework

A comprehensive security testing framework for modern and legacy vulnerabilities. This project is designed to help security professionals and developers identify vulnerabilities in web applications, networks, systems, and mobile applications.

## Features

- **Web Security Modules**: Test for SQL Injection, XSS, CSRF, Directory Traversal, and Remote Code Execution (RCE).
- **Network Security Modules**: Port scanning, packet analysis, and Nmap integration for network security testing.
- **System Security Modules**: Privilege escalation tests and rootkit detection for Linux and Windows systems.
- **Mobile Security Modules**: Security testing for Android and iOS applications using Frida.
- **Automated Scanning**: Integration with OWASP ZAP and Nmap for automated scanning.
- **Detailed Reporting**: JSON reports generated for all detected vulnerabilities.

## Getting Started

### Prerequisites

- Python 3.x
- Virtual environment tools like `venv` or `virtualenv`
- Required Python libraries specified in `requirements.txt`

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/oaslananka/security-testing-framework.git
    ```

2. Navigate into the project directory:

    ```bash
    cd security-testing-framework
    ```

3. Set up a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scriptsctivate`
    ```

4. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

### Usage

Run the main script to start security tests:

```bash
python main.py --url <target_url> --test <test_type> --param <parameter_name>
```

#### Example

```bash
python main.py --url http://example.com --test sql --param search
```

Supported test types:

- `sql`: SQL Injection testing
- `xss`: Cross-Site Scripting testing
- `rce`: Remote Code Execution testing

### Running Tests

To run the unit tests, use the following command:

```bash
pytest tests/
```

Make sure to set the `PYTHONPATH` correctly if needed:

```bash
set PYTHONPATH=%CD%  # On Windows
export PYTHONPATH=$(pwd)  # On Linux/macOS
```

### Directory Structure

```bash
security-testing-framework/
│
├── modules/
│   ├── web_security/
│   ├── network_security/
│   ├── system_security/
│   ├── mobile_security/
│   └── reporting/
│
├── tests/
├── main.py
├── requirements.txt
└── README.md
```

### Contributing

1. Fork the repository.
2. Create your feature branch:

    ```bash
    git checkout -b my-new-feature
    ```

3. Commit your changes:

    ```bash
    git commit -m 'Add some feature'
    ```

4. Push to the branch:

    ```bash
    git push origin my-new-feature
    ```

5. Open a pull request.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

For any questions or suggestions, feel free to open an issue or contact me directly.
