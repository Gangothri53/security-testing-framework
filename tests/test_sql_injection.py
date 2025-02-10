import unittest
from modules.web_security.sql_injection import SQLInjectionTester


class TestSQLInjection(unittest.TestCase):
    """
    A test case class for testing SQL injection vulnerabilities.

    Methods:
    - test_run_test: Tests the run_test method of the SQLInjectionTester class.
    """

    """
    Tests the run_test method of the SQLInjectionTester class.

    This method creates an instance of the SQLInjectionTester class with a specified URL and query parameter.
    It then calls the run_test method and asserts that the returned results are of type list.
    Finally, it iterates over the results and asserts that each found value is either True or False.
    """


def test_run_test(self):
    tester = SQLInjectionTester("http://example.com", "q")
    results = tester.run_test()
    self.assertIsInstance(results, list)
    for payload, found in results:
        self.assertIn(found, [True, False])


if __name__ == "__main__":
    unittest.main()
