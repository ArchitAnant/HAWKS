from weasyprint import HTML,CSS
import os
import csv
import time
import csv
import matplotlib.pyplot as plt
from datetime import datetime
from scapy.layers.inet import IP_PROTOS


def load_data():
    print("Generating Report...")
    data = []
    with open("dataset.csv",'r')as f:
            reader = csv.reader(f)
            for row in reader:
                data.append(
                    {
                    'destination_ips': row[0],
                    'source_ips': row[1],
                    'time_variance': row[2],
                    'max_occuring_byte_size': row[3],
                    'byte_size_variance': row[4],
                    'protocols': row[5],
                    'number_of_packets' : row[6],
                    'label': row[7]
                    }
                )

    data = data[1:]
    return data

def get_dest_ips(data):
    dest_ips = set()
    for i in data:
        if i['label'] == '1':
            list_of_ips = i['destination_ips'].split(',')
            for i in list_of_ips:
                dest_ips.add(i)
    
    return dest_ips

def get_src_ips(data):
    dest_ips = set()
    for i in data:
        if i['label'] == '1':
            list_of_ips = i['source_ips'].split(',')
            for i in list_of_ips:
                dest_ips.add(i)
    
    return dest_ips


def resolve_packet(data):
    protocols = set()
    for i in data:
        if i['label'] == '1':
            list_of_protocols = i['protocols'].split(',')
            for k in list_of_protocols:
                protocols.add(IP_PROTOS[eval(k)])
    return protocols
    
def get_downtime(data):
    total_time = 0
    for i in data:
        if i['label'] == '1':
            total_time+=5
    
    return total_time


def plot_packet_frame(list_of_frames,initial_time):
    list_of_packets = []
    utc_time = datetime.fromtimestamp(initial_time)
    time_list = [utc_time.strftime("%H:%M:%S")]

    for i in list_of_frames:
        list_of_packets.append(eval(i['number_of_packets']))
        temp  = initial_time+(5*(list_of_frames.index(i)+1))
        utc_time = datetime.fromtimestamp(temp)
        formatted_time = utc_time.strftime("%H:%M:%S")
        time_list.append(formatted_time)

    time_list = time_list[:-1]
    highlight_indices = []
    for i in range(len(list_of_packets)):
        if list_of_frames[i]['label'] == '1':
            highlight_indices.append(i)

    plt.plot(time_list, list_of_packets, marker='o', linestyle='-', color='b', label='Packet Flow rate')
    plt.plot(
        [time_list[i] for i in highlight_indices],  
        [list_of_packets[i] for i in highlight_indices],  
        marker='o', linestyle='None', color='red', markersize=10, label='Possible Attack Phase'
    )
    plt.xticks(rotation=90)
    plt.xlabel('Time (seconds)->')      
    plt.ylabel('Packet Count ->')  
    plt.title('Packet Flow rate') 

    plt.grid(False)
    plt.legend()
    plot_image = 'scripts/static/plot.png'
    plt.tight_layout()
    plt.savefig(plot_image)
    plt.close()
    plt.show()


def generate_report(start_time):
    data = load_data()
    plot_packet_frame(data,start_time)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>HAWKS Report</title>
        <link rel="stylesheet" href="scripts/static/tailwind-output.css">
        <header class="bg-gray-900 pb-2">
        <div class="h-2"></div>
         <div class="flex flex-row">
            <div class="w-5 h-5"></div>
            <h1 class="text-4xl font-bold text-white">HAWKS</h1>
        </div>
        <div class="flex flex-row">
            <div class="w-5"></div>
            <h1 class="text-m text-gray-400">Network Report</h1>
        </div>
        <div class="h-2"></div>
    </header>
</head>
<body class="text-gray-800">
        <div class="flex flex-col items-center p-8">
            <img src="file://{os.path.abspath("scripts/static/plot.png")}" alt="Flow Image" class="rounded mt-4 ">
            <div class="flex flex-row">
                <div class="flex flex-col">
                    <p class="text-lg font-bold mt-4 mb-2 border-b border-gray-300">Source IPs</p>
                    <p class="text-m mb-2">{"<br>".join(get_src_ips(data))}</p>
                </div>
                <div class="flex flex-col w-20">
                </div>    
                <div class="flex flex-col">
                    <p class="text-lg font-bold mt-4 mb-2 border-b border-gray-300">Destination IPs</p>
                    <p class="text-m mb-2">{"<br>".join(get_dest_ips(data))}</p>
                </div>
            </div>
            <div class="flex flex-row">
                <div class="flex flex-col">
                    <p class="text-lg font-bold mt-4 mb-2 border-b border-gray-300">Common Protocol(s)</p>
                    <p class="text-m mb-2">{"<br>".join(resolve_packet(data))}</p>
                </div>
                <div class="flex flex-col w-20"></div>
                <div class="flex flex-col">
                    <p class="text-lg font-bold mt-4 mb-2 border-b border-gray-300">Common Packet Size(s)</p>
                    <p class="text-m mb-2">1242<br>64</p>
                </div>
            </div>
            <p class="text-lg font-bold mt-4">Total Downtime : {get_downtime(data)} seconds</p>
            
        </div>
         <footer class="border-t border-gray-300 mt-4 pt-4">
                <p class="text-sm text-gray-600">Every metric except the graph is observed for just the attack phase.<br>Network report can have discrepancies. Verify with system before any action</p>
    </footer>
    </body>
   
    </html>
    """

    HTML(string=html_content).write_pdf('./report.pdf',stylesheets=[CSS('scripts/static/report.css')])


generate_report(time.time())