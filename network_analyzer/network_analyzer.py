import scapy.all as scapy
import argparse

def capture_packets(interface, protocol=None, ip=None):
    if protocol and ip:
        filter = f"ip.proto == {protocol} and host {ip}"
    elif protocol:
        filter = f"ip.proto == {protocol}"
    elif ip:
        filter = f"host {ip}"
    else:
        filter = ""

    scapy.sniff(iface=interface, store=False, prn=process_packet, filter=filter)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        print(f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}")

    if packet.haslayer(scapy.TCP):
        tcp_layer = packet.getlayer(scapy.TCP)
        print(f"Protocol: TCP, Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        #print(f"Payload: {packet.payload}") # Removed to avoid printing raw payload

    elif packet.haslayer(scapy.UDP):
        udp_layer = packet.getlayer(scapy.UDP)
        print(f"Protocol: UDP, Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        #print(f"Payload: {packet.payload}") # Removed to avoid printing raw payload

    elif packet.haslayer(scapy.ICMP):
        print("Protocol: ICMP")
        #print(f"Payload: {packet.payload}") # Removed to avoid printing raw payload
    print("---------------------------------------------------")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("-i", "--interface", dest="interface", default="Ethernet", help="Network interface to capture packets from")
    parser.add_argument("-p", "--protocol", dest="protocol", help="Filter by protocol (e.g., tcp, udp, icmp)")
    parser.add_argument("-ip", "--ip", dest="ip", help="Filter by IP address")
    args = parser.parse_args()

    print("Make sure you are running this script with root privileges.")
    print("This tool should only be used for educational purposes and ethical network analysis.")

    capture_packets(args.interface, args.protocol, args.ip)
