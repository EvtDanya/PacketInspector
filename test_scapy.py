from scapy.all import *

filter = "host 192.168.0.11"

def packet_handler(packet):
    print('Hello')
    print(packet.summary())
    
if __name__ == "__main__":
    sniff(filter=filter, prn=packet_handler)