import unittest
import os
from modules.reporting.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """
    Test case to verify the functionality of the save_report method in the ReportGenerator class.
    The test case performs the following steps:
    1. Creates a sample data list containing a dictionary with information about a security issue.
    2. Initializes a ReportGenerator object with the sample data.
    3. Calls the save_report method of the ReportGenerator object, passing the filename "test_report.json".
    4. Asserts that the "test_report.json" file exists.
    5. Reads the content of the "test_report.json" file and asserts that it contains the string "SQL Injection".
    6. Removes the "test_report.json" file.
    This test case ensures that the save_report method correctly generates a report file with the expected content.
    """

    def test_save_report(self):
        data = [{"type": "SQL Injection", "severity": "High"}]
        generator = ReportGenerator(data)
        generator.save_report("test_report.json")

        self.assertTrue(os.path.exists("test_report.json"))
        with open("test_report.json", "r") as file:
            content = file.read()
            self.assertIn("SQL Injection", content)

        os.remove("test_report.json")


if __name__ == "__main__":
    unittest.main()
