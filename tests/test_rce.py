import unittest
from modules.web_security.rce import RCETester


class TestRCETester(unittest.TestCase):
    """
    Test case for the `run_test` method of the `RCETester` class.

    This test case verifies that the `run_test` method returns a list of tuples,
    where each tuple contains a payload and a boolean value indicating whether
    the payload was found or not.

    The test creates an instance of the `RCETester` class with a sample URL and
    command payload. It then calls the `run_test` method and asserts that the
    returned results are of type list. It also checks that each tuple in the
    results list contains a boolean value that is either `True` or `False`.
    """

    def test_run_test(self):
        tester = RCETester("http://example.com", "cmd")
        results = tester.run_test()
        self.assertIsInstance(results, list)
        for payload, found in results:
            self.assertIn(found, [True, False])


if __name__ == "__main__":
    unittest.main()
