
#!/usr/bin/env python
"""
This tool will help us to detect any Deauth attacks in the system 
By analyzing the output packet count, we can detect whether the system is under the DoS attack or not
"""


from scapy.all import *
from scapy.layers import Dot11

# get Network Interface from user
interface = raw_input('Enter your Network Interface > ')

# set Packet Counter 
Packet_Counter = 1

# extract info of the packet 
def info(packet):
    if packet.haslayer(Dot11):
        # The packet.subtype==12 statement indicates the deauth frame
        if ((packet.type == 0) & (packet.subtype==12)):
            global Packet_Counter
            print ("[+] Deauthentication Packet detected ! ", Packet_Counter)
            Packet_Counter = Packet_Counter + 1

# Start Sniffing and Detecting Deauth Packets
sniff(iface=interface,prn=info)