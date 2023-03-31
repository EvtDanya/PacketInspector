import socket
import os
import struct
from ctypes import *

HOST = '172.20.10.4'

class IP(Structure):
    _fields_ = [
        ('ihl',          c_ubyte,  4),
        ('version',      c_ubyte,  4),
        ('tos',          c_ubyte,  8),
        ('len',          c_ushort, 16),
        ('id',           c_ushort, 16),
        ('offset',       c_ushort, 16),
        ('ttl',          c_ubyte,  8),
        ('protocol_num', c_ubyte,  8),
        ('sum',          c_ushort,  16),
        ('src',          c_uint32,  32),
        ('dst',          c_uint32,  32),
    ]
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

def main():
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
    print(sniffer.recvfrom(65565))
    
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    
if __name__ == '__main__':
    main()