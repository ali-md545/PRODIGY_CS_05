#A simple packet sniffer in Python by Muhammad Ali Raja

import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None

        print(f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

        if payload:
            print(f"Payload: {payload.hex()}")  # Display payload in hexadecimal format

def main():
    interface = input("Enter the interface to sniff (e.g., eth0): ")
    sniff_packets(interface)

if __name__ == "__main__":
    main()
