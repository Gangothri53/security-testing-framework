import unittest
from modules.web_security.xss import XSSTester


class TestXSSTester(unittest.TestCase):
    """
    Test case for running XSS test.

    This test case creates an instance of XSSTester class with a target URL and a query parameter.
    It then runs the test and asserts that the results are of type list.
    Finally, it iterates over the results and asserts that each found value is either True or False.
    """

    def test_run_test(self):
        tester = XSSTester("http://example.com", "q")
        results = tester.run_test()
        self.assertIsInstance(results, list)
        for payload, found in results:
            self.assertIn(found, [True, False])


if __name__ == "__main__":
    unittest.main()
