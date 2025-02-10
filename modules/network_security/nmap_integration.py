import subprocess


class NmapScanner:
    """
    Initializes a new instance of the NmapScanner class.
    Parameters:
    - target_ip (str): The IP address of the target to scan.
    """
    """
    Runs an Nmap scan on the target IP address.
    Returns:
    - str: The output of the Nmap scan.
    """

    def __init__(self, target_ip):
        self.target_ip = target_ip

    def run_scan(self):
        result = subprocess.run(
            ["nmap", "-sV", self.target_ip], capture_output=True, text=True)
        return result.stdout
