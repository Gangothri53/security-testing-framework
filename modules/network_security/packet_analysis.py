from scapy.all import *


class PacketAnalyzer:
    """
    A class for analyzing network packets.
    Args:
        interface (str): The name of the network interface to capture packets from.
    Attributes:
        interface (str): The name of the network interface.
    Methods:
        capture_packets(count=10): Captures network packets from the specified interface.
        analyze_packets(packets): Analyzes the captured packets.
    """
    """
    Captures network packets from the specified interface.
    Args:
        count (int): The number of packets to capture. Default is 10.
    Returns:
        list: A list of captured packets.
    """

    """
    Analyzes the captured packets.
    Args:
        packets (list): A list of network packets to analyze.
    Returns:
        None
    """

    def __init__(self, interface):
        self.interface = interface

    def capture_packets(self, count=10):
        packets = sniff(iface=self.interface, count=count)
        return packets

    def analyze_packets(self, packets):
        for packet in packets:
            print(packet.summary())
