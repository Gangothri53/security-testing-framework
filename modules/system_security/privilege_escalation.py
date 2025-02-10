import subprocess


class PrivilegeEscalationTester:
    """
    Initializes a PrivilegeEscalationTester object.
    Parameters:
    - target_system (str): The target system to test for privilege escalation.
    Returns:
    - None
    """
    """
    Runs the privilege escalation test on the target system.
    Returns:
    - str: The output of the test.
    """

    def __init__(self, target_system):
        self.target_system = target_system

    def run_test(self):
        result = subprocess.run(["sudo", "-l"], capture_output=True, text=True)
        return result.stdout
