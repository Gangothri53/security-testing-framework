import json


class ReportGenerator:
    """
    Initializes a ReportGenerator object.
    Args:
        report_data (dict): The data to be included in the report.
    """
    """
    Saves the report data to a JSON file.
    Args:
        filename (str, optional): The name of the file to save the report to. Defaults to "report.json".
    """

    def __init__(self, report_data):
        self.report_data = report_data

    def save_report(self, filename="report.json"):
        with open(filename, "w") as file:
            json.dump(self.report_data, file, indent=4)
