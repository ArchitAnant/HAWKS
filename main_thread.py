from scapy.all import sniff
import statistics as st
import csv
import threading
import tensorflow as tf
import numpy as np
from sklearn.preprocessing import LabelEncoder
import time
from scripts.report import generate_report
import subprocess as sb
import platform
from scripts.util import preprocess_sequence_input
from scripts.train import TransformerBlock

label_encoder = LabelEncoder()

model = tf.keras.models.load_model(
    'prediction_model.keras',
    custom_objects={"TransformerBlock": TransformerBlock}
    )
# Global variables to store packet data
dest_ips = set()
scr_ips = set()
time_list = []
size_list = []
protocol_set = set()

start_time = 0

hold_list = []
stop_sniffing = False  # Flag to control the sniffing process


def process_packet(packet):
    """Process each packet captured by sniff"""
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        packet_size = len(packet)
        timestamp = packet.time

        scr_ips.add(src_ip)
        dest_ips.add(dst_ip)
        protocol_set.add(protocol)
        time_list.append(timestamp)
        size_list.append(packet_size)

def sniff_packets():
    """Sniff packets in a separate thread"""
    global stop_sniffing
    while not stop_sniffing:
        sniff(timeout=5, prn=process_packet, store=0)

# CSV file setup
headers = ['destination_ips', 'source_ips', 'time_variance', 'max_occuring_byte_size', 'byte_size_variance', 'protocols', 'number_of_packets', 'label']
with open("dataset.csv", "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=headers)
    writer.writeheader()

# Start sniffing in a separate thread
start_time = time.time()
sniff_thread = threading.Thread(target=sniff_packets)
sniff_thread.start()

temp = []

try:
    while True:
        time.sleep(5)
        if len(time_list) > 1:
            time_variance = st.variance(time_list)
        else:
            time_variance = 0

        if len(size_list) > 1:
            pakt_size = [st.mode(size_list), st.variance(size_list)]
        else:
            pakt_size = [0, 0]

        dest_ip_str = ','.join(dest_ips)
        src_ip_str = ','.join(scr_ips)
        protocol_set_str = ','.join(map(str, sorted(protocol_set)))

        # Prepare data for the model
        data = {
            'destination_ips': dest_ip_str,
            'source_ips': src_ip_str,
            'time_variance': time_variance,
            'max_occuring_byte_size': pakt_size[0],
            'byte_size_variance': pakt_size[1],
            'protocols': protocol_set_str,
            'number_of_packets': len(size_list)
            # 'label': 1
        }
        print(data)
        if data['number_of_packets']!=0:
            temp.append(data)

        if len(temp)==5:
            input_data = np.expand_dims(preprocess_sequence_input(temp), axis=0)
            ans = model.predict(input_data)
            out = (ans > 0.5).astype(int) 
            if out == 0:
                encoded_label = "Normal"
                temp[0]['label'] = 0
                temp[1]['label'] = 0
                temp[2]['label'] = 0
                temp[3]['label'] = 0
                temp[4]['label'] = 0

            else:
                encoded_label = "Attack"
                temp[0]['label'] = 1
                temp[1]['label'] = 1
                temp[2]['label'] = 1
                temp[3]['label'] = 1
                temp[4]['label'] = 1
            
            print(f"Decoded label: {encoded_label}")
            

            if len(dest_ip_str) != 0:
                with open("dataset.csv", "a", newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writerows(temp)
            
            temp.clear()

        # Clear sets and lists for the next iteration
        dest_ips.clear()
        scr_ips.clear()
        time_list.clear()
        size_list.clear()
        protocol_set.clear()
        

except KeyboardInterrupt:
    print("\nStopping packet sniffing...")
    generate_report(start_time)
    stop_sniffing = True
    sniff_thread.join()
    os_type = platform.system()
    if os_type == 'Darwin':
        try:
            sb.Popen(['open', 'tests/output.pdf'])
        except:
            print("Error launching the Report!")
    elif os_type == 'Linux':
        try:
            sb.Popen(['mupdf', 'tests/output.pdf'])
        except FileNotFoundError:
            print("\nmupdf not found\nInstalling\n")
            sb.run("sudo apt install mupdf -y",shell=True)
            sb.Popen(['mupdf', 'tests/output.pdf'])
        except Exception as e:
            print("Error launching the Report!")

print("Sniffing stopped.")