from scapy.all import *

def packet_callback(packet):
    src = packet[IP].src
    dst = packet[IP].dst
    proto = packet[IP].proto
    length = len(packet)
    data = packet.load
    print(f"{src} -> {dst}: {length} bytes, Protocol: {proto}")
    print(f"Data: {data}")
    print(packet.summary(), '\n')

sniff(filter="tcp", prn=packet_callback, count=10)