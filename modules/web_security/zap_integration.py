import subprocess


class OWASPZAPIntegration:
    """
    Initializes an instance of OWASPZAPIntegration.
    Parameters:
    - target_url (str): The URL of the target website to scan.
    """
    """
    Runs the OWASP ZAP scan on the target URL.
    Returns:
    - str: The output of the scan as a string.
    """

    def __init__(self, target_url):
        self.target_url = target_url

    def run_scan(self):
        subprocess.run(["zap-cli", "start"])
        subprocess.run(["zap-cli", "open-url", self.target_url])
        subprocess.run(["zap-cli", "spider", self.target_url])
        subprocess.run(["zap-cli", "active-scan", self.target_url])
        result = subprocess.run(["zap-cli", "alerts"],
                                capture_output=True, text=True)
        return result.stdout
