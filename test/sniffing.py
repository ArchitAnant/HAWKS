from scapy.all import sniff
# from datetime import datetime
import statistics as st
import csv

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

# Start sniffing the network traffic
headers = ['destination_ips','source_ips','time_variance','max_occuring_byte_size','byte_size_variance','protocols','number_of_packets','label']
with open("dataset.csv","w",newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

while True:
    sniff(timeout = 5,prn=process_packet, store=0)
    print("Done with one")
    if len(time_list)>1:
        time_variance = st.variance(time_list)
    else: 
        time_variance = 0
    if len(size_list)>1:
        pakt_size = [st.mode(size_list),st.variance(size_list)]
    else:
          pakt_size = [0,0]
    # print(f"dest ip : {dest_ips}\nsrc ips : {scr_ips}\ntimes : {time_variance}\nSizes : {pakt_size}\nProtocols : {protocol_set}\nNo. of packets: {len(size_list)}")
    dest_ip_str = ''

    for i in dest_ips:
        dest_ip_str+=f'{i},'

    dest_ip_str = dest_ip_str[:len(dest_ip_str)-1]

    src_ip_str = ''
    for i in scr_ips:
        src_ip_str+=f'{i},'

    src_ip_str = src_ip_str[:len(src_ip_str)-1]

    protocol_set_str = ''
    for i in protocol_set:
        protocol_set_str+=f'{i},'

    protocol_set_str = protocol_set_str[:len(protocol_set_str)-1]
    
    data = [
    {
        'destination_ips': dest_ip_str,
        'source_ips': src_ip_str,
        'time_variance': time_variance,
        'max_occuring_byte_size': pakt_size[0],
        'byte_size_variance': pakt_size[1],
        'protocols': protocol_set_str,
        'number_of_packets' : len(size_list),
        'label': 'Normal'
    }
    # Add more records as needed
    ]
    
    if(len(dest_ip_str)!=0):
        with open("dataset.csv","a",newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            
            writer.writerows(data)

    print(data)
    dest_ips.clear()
    scr_ips.clear()
    time_list.clear()
    size_list.clear()
    protocol_set.clear()



"""
every dump_pack:
    1. time variance
    2. source ips
    3. dest ips
    4. size(mode,variance)
    5. protocol

    time_variance, source_ips, destination_ips, max_occuring_byte_size, byte_size_variance, protocols 

    destination_ips : ['142.250.193.206', '192.168.189.50']
    source_ips : ['142.250.193.206', '192.168.189.50']
    time_variance : 1.4268018026245133
    max_occuring_byte_size : 98
    byte_size_variance : 0
    protocols : [1]
    label : Normal


    [{'destination_ips': '49.44.176.57,192.168.189.50,49.44.176.8,20.42.73.27', 'source_ips': '49.44.176.57,192.168.189.50,49.44.176.8,20.42.73.27', 'time_variance': 0.17850368233352876, 'max_occuring_byte_size': 1242, 'byte_size_variance': 287793.10714285716, 'protocols': '17,6,1', 'number_of_packets': 36, 'label': 'Normal'}]
"""