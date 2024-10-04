import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import optparse


def get_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--interface", dest = "interface", help = "Write interface!")
    (user_input,arguments) = parse_object.parse_args()
    return user_input

def get_packet(interface):
    scapy.sniff(iface=interface, store=False, prn=analyse_packet)

def analyse_packet(packet):
    # Check if the packet contains an HTTP Request
    if packet.haslayer(HTTPRequest):
        print("[+] HTTP Request found")

        # Extract and print the Host and Path of the HTTP request
        if packet[HTTPRequest].Host and packet[HTTPRequest].Path:
            print(f"Host: {packet[HTTPRequest].Host.decode()} | Path: {packet[HTTPRequest].Path.decode()}")

        # Check for raw data in the packet (which might contain the HTTP payload)
        if packet.haslayer(scapy.Raw):
            print(f"Raw Data: {packet[scapy.Raw].load.decode(errors='ignore')}")

# Start sniffing on the specified interface (e.g., eth0)
user_interface = get_input().interface
get_packet(user_interface)
