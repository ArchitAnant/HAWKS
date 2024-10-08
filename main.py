from scapy.all import sniff
import statistics as st
import csv
import tensorflow as tf
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
label_encoder = LabelEncoder()

model = tf.keras.models.load_model('./prediction_model.h5')

dest_ips = set()
scr_ips = set()
time_list = []
size_list = []
protocol_set = set()

hold_list = []

def preprocess_single_input(input_row):
    source_ips = input_row['source_ips']
    destination_ips = input_row['destination_ips']
    time_variance = input_row['time_variance']
    max_occuring_byte_size = input_row['max_occuring_byte_size']
    byte_size_variance = input_row['byte_size_variance']
    protocols = input_row['protocols']
    number_of_packets = input_row['number_of_packets']

    source_ip_count = len(set(source_ips.split(','))) if isinstance(source_ips, str) else 0
    destination_ip_count = len(set(destination_ips.split(','))) if isinstance(destination_ips, str) else 0


    protocol_count = len(set(protocols.split(','))) if isinstance(protocols, str) else 0

    features = np.array([
        source_ip_count,        # Count of unique source IPs
        destination_ip_count,   # Count of unique destination IPs
        time_variance,          # Time variance between packets
        max_occuring_byte_size, # Maximum occurring byte size
        byte_size_variance,     # Variance of byte sizes
        protocol_count,         # Count of unique protocols
        number_of_packets       # Number of packets observed
    ]).reshape(1, -1)

    data = pd.read_csv('datasets/collection_dataset.csv')

    data['source_ip_count'] = data['source_ips'].apply(lambda x: len(set(x.split(','))))
    data['destination_ip_count'] = data['destination_ips'].apply(lambda x: len(set(x.split(','))))

    data['protocol_count'] = data['protocols'].apply(lambda x: len(set(x.split(','))))

    data = data.drop(['source_ips', 'destination_ips', 'protocols'], axis=1)

    X = data.drop('label', axis=1)
    y = data['label']

    X_train, _, _, _ = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    normalized_features = scaler.transform(features)

    return normalized_features


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

headers = ['destination_ips','source_ips','time_variance','max_occuring_byte_size','byte_size_variance','protocols','number_of_packets','label']
with open("dataset.csv","w",newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

while True:
    try:
        sniff(timeout = 5,prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Yes Intrupt")
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
    ]
    print(data)
    if not data[0]['number_of_packets'] == 0:
        ans = model.predict(preprocess_single_input(data[0]))
        if int(ans[0][0]) == 0:
            encoded_label   = "Normal"
            data[0]['label'] = 0
        else:
            encoded_label = "Attack"
            data[0]['label'] = 1
        print(f"Decoded label: {encoded_label}")

    
    dest_ips.clear()
    scr_ips.clear()
    time_list.clear()
    size_list.clear()
    protocol_set.clear()
