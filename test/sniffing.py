from scapy.all import sniff
from datetime import datetime
import statistics as st

# Function to process each packet
dest_ips = set()
scr_ips = set()
time_list = []
size_list = []

protocol_set = set()

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
        timestamp = packet.time#datetime.now().second()

        scr_ips.add(src_ip)
        dest_ips.add(dst_ip)
        protocol_set.add(protocol)
        time_list.append(timestamp)
        size_list.append(packet_size)

        # print(f'Time: {timestamp}, Source IP: {src_ip}, Destination IP: {dst_ip}, Size: {packet_size} bytes, Protocol: {protocol}')

# Start sniffing the network traffic
while True:
    sniff(timeout =5,prn=process_packet, store=0)
    print("Done with one")
    # need to handle when there are 0 or 1 items for variance calculation 
    time_variance = st.variance(time_list)
    pakt_size = [st.mode(size_list),st.variance(size_list)]
    print(f"dest ip : {dest_ips}\nsrc ips : {scr_ips}\ntimes : {time_variance}\nSizes : {pakt_size}")
    dest_ips.clear()
    scr_ips.clear()
    time_list.clear()
    size_list.clear()



"""
every dump_pack:
    1. time variance
    2. source ip
    3. dest ip
    4. size(mode,variance)
    5. protocol
"""