import requests


class XSSTester:
    """
    Class for testing XSS vulnerabilities in a target URL.
    Args:
        target_url (str): The URL of the target website.
        param (str): The parameter to test for XSS vulnerabilities.
    Attributes:
        target_url (str): The URL of the target website.
        param (str): The parameter to test for XSS vulnerabilities.
        payloads (list): List of XSS payloads to test.
    Methods:
        run_test: Runs the XSS testing and returns the results.
    """
    """
    Runs the XSS testing and returns the results.
    Returns:
        list: List of tuples containing the payload and a boolean indicating if the payload was successful.
    """

    def __init__(self, target_url, param):
        self.target_url = target_url
        self.param = param
        self.payloads = [
            "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]

    def run_test(self):
        results = []
        for payload in self.payloads:
            test_url = f"{self.target_url}?{self.param}={payload}"
            response = requests.get(test_url)
            if payload in response.text:
                results.append((payload, True))
            else:
                results.append((payload, False))
        return results
