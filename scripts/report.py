import csv
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import time
from datetime import datetime, timedelta
from scapy.layers.inet import IP_PROTOS

def get_dest_ips(data):
    dest_ips = set()
    for i in data:
        if i['label'] == '1':
            list_of_ips = i['destination_ips'].split(',')
            for i in list_of_ips:
                dest_ips.add(i)
    
    # print(dest_ips)
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
    desc_dict = {}
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
    # gmt_plus_530 = utc_time + timedelta(hours=5, minutes=30)
    time_list = [utc_time.strftime("%H:%M:%S")]

    for i in list_of_frames:
        list_of_packets.append(eval(i['number_of_packets']))
        temp  = initial_time+(5*(list_of_frames.index(i)+1))
        utc_time = datetime.fromtimestamp(temp)
        # gmt_plus_530 = utc_time + timedelta(hours=5, minutes=30)
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
        marker='o', linestyle='None', color='red', markersize=10, label='Attack Packets'
    )
    plt.xticks(rotation=90)
    plt.xlabel('Time (seconds)->')      
    plt.ylabel('Packet Count ->')  
    plt.title('Packet Flow rate') 

    plt.grid(False)
    plt.legend()
    plot_image = 'tests/plot.png'
    plt.tight_layout()
    plt.savefig(plot_image)
    plt.close()
    plt.show()

def generate_report(start_time):
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

    pdf_file = 'tests/output.pdf'
    c = canvas.Canvas(pdf_file, pagesize=letter)
    width, height = letter

    plot_packet_frame(data,start_time)
    c.drawImage("tests/plot.png", x=100, y=height/2, width=400, height=300)

    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, height - 50, "DoS Report")

    text = c.beginText(100, height/2-50)

    
    text.textLine("Source IPs:")
    text.setFont("Helvetica", 12)
    list_of_scr_ips = get_src_ips(data)
    # print(list_of_scr_ips)
    text.textLines('\n'.join(list_of_scr_ips))

    text.setFont("Helvetica-Bold", 14)
    text.textLines("Destination IPs:")
    text.setFont("Helvetica", 12)
    list_of_scr_ips = get_dest_ips(data)
    text.textLines("\n".join(list_of_scr_ips))

    text.setFont("Helvetica-Bold", 14)
    text.textLine("Common Protocol(s):")
    text.setFont("Helvetica", 12)
    list_of_proto = resolve_packet(data)
    text.textLines("\n".join(list_of_proto))

    text.setFont("Helvetica-Bold", 14)
    text.textLine("Total Downtime (seconds):")
    text.setFont("Helvetica", 12)
    # list_of_proto = get_downtime(data)
    text.textLine(f"{get_downtime(data)}")


    c.drawText(text)
    c.save()

    print(f"Report created successfully : {pdf_file}")                      

# generate_report(time.time())