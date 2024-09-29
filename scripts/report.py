import csv
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

data = [
    
]

with open("tests/backTemp.csv",'r')as f:
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


# extract the destination ips from the data if label is attack i.e = 1!
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
            list_of_protocols = set(i['protocols'].split(','))
            if len(protocols) > 0:
                protocols = protocols.intersection(list_of_protocols)
            else:
                protocols = list_of_protocols
            # for i in list_of_protocols:
            #     protocols.add(i)
    
    return protocols
    
def get_downtime(data):
    total_time = 0
    for i in data:
        if i['label'] == '1':
            total_time+=5
    
    return total_time


def plot_packet_frame(list_of_frames):
    list_of_packets = []
    time_list = [1]
    for i in list_of_frames[1:]:
        list_of_packets.append(eval(i['number_of_packets']))
        time_list.append(time_list[len(time_list)-1]+5)

    time_list = time_list[:-1]
    highlight_indices = [i for i in range( 2 , len(time_list)-2)] 

    plt.plot(time_list, list_of_packets, marker='o', linestyle='-', color='b', label='Packet Flow rate')
    plt.plot(
        [time_list[i] for i in highlight_indices],  
        [list_of_packets[i] for i in highlight_indices],  
        marker='o', linestyle='None', color='red', markersize=10, label='Attack Packets'
    )
    plt.xlabel('Time (seconds)->')      
    plt.ylabel('Packet Count ->')  
    plt.title('Packet Flow rate') 

    plt.grid(False)
    plt.legend()
    plot_image = 'tests/plot.png'
    plt.savefig(plot_image)
    plt.close()
    plt.show()

def generate_report(data):
    pdf_file = 'tests/output.pdf'
    c = canvas.Canvas(pdf_file, pagesize=letter)
    width, height = letter

    plot_packet_frame(data)
    c.drawImage("tests/plot.png", x=100, y=height/2, width=400, height=300)

    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, height - 50, "DoS Report")

    text = c.beginText(100, height/2-50)

    
    text.textLine("Source IPs:")
    text.setFont("Helvetica", 12)
    list_of_scr_ips = get_src_ips(data)
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

    print(f"PDF created successfully: {pdf_file}")                      


# print(get_dest_ips(data))
# print()
# print(get_src_ips(data))
# print()
# print(resolve_packet(data))
# print()
# print(get_downtime(data))
# plot_packet_frame(data)
generate_report(data)

