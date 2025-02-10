import subprocess


class PortScanner:
    """
    Initializes a PortScanner object.
    Args:
        target_ip (str): The IP address of the target to scan.
    """
    """
    Runs a port scan on the target IP address using the nmap tool.
    Returns:
        str: The output of the port scan.
    """

    def __init__(self, target_ip):
        self.target_ip = target_ip

    def run_scan(self):
        result = subprocess.run(
            ["nmap", "-sV", self.target_ip], capture_output=True, text=True)
        return result.stdout
