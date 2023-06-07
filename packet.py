import struct
import ipaddress
import dpkt
from print import print_color

class PacketFactory:
  '''
  Factory class
  '''
  @staticmethod
  def create_packet(system, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None, timestamp=None, raw=None, num=None):  
    if ip_protocol_num == 6:
      return TCPPacket(PacketFactory.get_format_char(system), buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
    elif ip_protocol_num == 17:
      return UDPPacket(PacketFactory.get_format_char(system), buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
    elif ip_protocol_num == 1:
      return ICMPPacket(PacketFactory.get_format_char(system), buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
    else:
      return Packet(PacketFactory.get_format_char(system), buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
  
  @staticmethod
  def get_format_char(system) -> str:
    return '!' if system == 'Windows' else '<'
  
class Packet:
  '''
  Class for packet parsing
  '''
  def __init__(self, format_char, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None, timestamp=None, raw=None, num=None) -> None:
    self.need_to_print_raw = raw
    self.timestamp = timestamp
    self.num = num
    
    # Parse the packet header
    header = struct.unpack(format_char +'BBHHHBBH4s4s', buff[0:20])  # ipv4 header, add ipv6 header in future versions  
    self.ihl = header[0] & 0xF
    self.tos = header[1]
    self.len = header[2]
    self.id = header[3]
    self.offset = header[4]
    self.ttl = header[5]
    self.sum = header[7]        
 
    if src_ip:
      self.src = src_ip
      self.src_address = ipaddress.ip_address(src_ip)
    else:
      self.src = header[8]  
      self.src_address = ipaddress.ip_address(self.src)
    
    if dst_ip:
      self.dst = dst_ip
      self.dst_address = ipaddress.ip_address(self.dst)
    else:
      self.dst = header[9]  
      self.dst_address = ipaddress.ip_address(self.dst)
    
    self.ver = ip_version if ip_version else header[0] >> 4 
    self.protocol_num = ip_protocol_num if ip_protocol_num else header[6]
    
    self.buff = buff
    
    try:
      self.protocol = {1:'ICMP', 6:'TCP', 17:'UDP'}[self.protocol_num]
    except Exception:
      self.protocol = 'Unsupported protocol'
  
  def print_less(self) -> None:
    print(f'No. {self.num} - {self.protocol}: {self.src_address} -> {self.dst_address}')
  
  def print_header(self) -> None:
    print_color(f'No. {self.num}\n[>] Header: ', 'yellow')
    print(f'  Version: {self.ver}')
    print(f'  Protocol Number: {self.protocol_num} -> {self.protocol}')
    print(f'  TTL: {self.ttl}')       
   
  def print_hexdump(self) -> None:
    hex_data = ' '.join(f'{byte:02x}' for byte in self.buff[20:])
    lines = [hex_data[i:i+48] for i in range(0, len(hex_data), 48)]
    for line in lines:
        print(f'  {line}')

  def print_ascii_data(self) -> None:
    ascii_data = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in self.buff[20:])
    print(f'  {ascii_data}')
  
  def print_raw(self) -> None:
    print(f' {self.buff[20:]}')
  
  def print_payload(self) -> None:
    print_color('[>] Payload:', 'yellow')
    
    if self.need_to_print_raw:
      print_color(' [*] Raw:', 'yellow')
      self.print_raw()
    
    print_color(' [*] Hex:', 'yellow')
    self.print_hexdump()
    
    print_color(' [*] ASCII data:', 'yellow')
    self.print_ascii_data()
    print('\n')
    
  def get_pcap_packet(self) -> bytes:
    ethernet_header = dpkt.ethernet.Ethernet(src=self.src, dst=self.dst, type=dpkt.ethernet.ETH_TYPE_IP)
    
    # Create IP headerc
    ip_header = dpkt.ip.IP()

    # Parse the IP header from the packet data
    ip_header.unpack(self.buff)

    # Combine the Ethernet header with the IP header and packet data
    ethernet_header.data = ip_header
    ethernet_header.data.data = self.buff[20:]
    
    return ethernet_header

class TCPPacket(Packet):
    def __init__(self, format_char, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None, timestamp=None, raw=None, num=None) -> None:
      super().__init__(format_char, buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
      self.src_port = None
      self.dst_port = None  
      self.parse_header(format_char)
      
    def parse_header(self, format_char) -> None:
      self.src_port, self.dst_port = struct.unpack(str(format_char) + 'HH', self.buff[20:24])
      
    def print_header(self) -> None:
      super().print_header()
      print(f'  Source IP: {self.src_address} Port: {self.src_port}')
      print(f'  Destination IP: {self.dst_address} Port: {self.dst_port}')

class UDPPacket(Packet):
    def __init__(self, format_char, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None, timestamp=None, raw=None, num=None) -> None:
      super().__init__(format_char, buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
      self.src_port = None
      self.dst_port = None 
      self.parse_header(format_char)
      
    def parse_header(self, format_char) -> None:
      udp_header = struct.unpack(str(format_char) + 'HHHH', self.buff[20:28])
      self.src_port = udp_header[0]
      self.dst_port = udp_header[1]
      
    def print_header(self) -> None:
      super().print_header()
      print(f'  Source IP: {self.src_address} Port: {self.src_port}')
      print(f'  Destination IP: {self.dst_address} Port: {self.dst_port}')

class ICMPPacket(Packet):
    def __init__(self, format_char, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None, timestamp=None, raw=None, num=None) -> None:
      super().__init__(format_char, buff, src_ip, dst_ip, ip_version, ip_protocol_num, timestamp, raw, num)
      self.type = None
      self.code = None 
      self.parse_header(format_char)
       
    def parse_header(self, format_char) -> None:
      icmp_header = struct.unpack(str(format_char) + 'BBHHH', self.buff[20:28])
      self.type = icmp_header[0]
      self.code = icmp_header[1]
      
    def print_header(self) -> None:  
      super().print_header()
      print(f'  Type: {self.type}')
      print(f'  Code: {self.code}')
      print(f'  Source IP: {self.src_address}')
      print(f'  Destination IP: {self.dst_address}') 
      