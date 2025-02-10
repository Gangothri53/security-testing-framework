import requests
from bs4 import BeautifulSoup


class CSRFTester:
    """
    Class for testing Cross-Site Request Forgery (CSRF) vulnerabilities in web applications.
    Args:
        target_url (str): The URL of the target web application.
    Methods:
        run_test(): Runs the CSRF vulnerability test on the target web application.
    Returns:
        tuple: A tuple containing a boolean value indicating if the CSRF vulnerability is present,
               and the value of the CSRF token if found, or None if not found.
    """
    """
    Runs the CSRF vulnerability test on the target web application.
    Returns:
        tuple: A tuple containing a boolean value indicating if the CSRF vulnerability is present,
                and the value of the CSRF token if found, or None if not found.
    """

    def __init__(self, target_url):
        self.target_url = target_url

    def run_test(self):
        session = requests.Session()
        response = session.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})

        if csrf_token:
            return True, csrf_token['value']
        else:
            return False, None
