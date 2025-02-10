import subprocess


class RootkitDetection:
    """
    A class for performing rootkit detection using the rkhunter tool.
    Methods:
        run_rkhunter: Runs the rkhunter tool and returns the output.
    """
    """
    Runs the rkhunter tool and returns the output.
    Returns:
        str: The output of the rkhunter tool.
    """

    def __init__(self):
        pass

    def run_rkhunter(self):
        result = subprocess.run(["rkhunter", "--check"],
                                capture_output=True, text=True)
        return result.stdout
