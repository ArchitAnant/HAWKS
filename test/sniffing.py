from scapy.all import sniff
from datetime import datetime

# Function to process each packet

def process_packet(packet):
    """
    •	1: ICMP (Internet Control Message Protocol)
	•	6: TCP (Transmission Control Protocol)
	•	17: UDP (User Datagram Protocol)
    """
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        packet_size = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f'Time: {timestamp}, Source IP: {src_ip}, Destination IP: {dst_ip}, Size: {packet_size} bytes, Protocol: {protocol}')

# Start sniffing the network traffic
sniff(prn=process_packet, store=0)