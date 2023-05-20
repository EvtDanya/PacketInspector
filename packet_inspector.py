import argparse
import platform

# pretty print
from colorama import init, Fore, Style
from prettytable import PrettyTable
import threading

import datetime
import logging

# for sniffing
import ifaddr
import socket 
import struct
import time
import ipaddress
import dpkt

# for running as admin
import ctypes
import sys
import os

# import graphics module
#from graphics import *

# import user
#from user import * 
 
def run_as_admin(system) -> None:
  '''
  Check if admin and run as admin if needed 
  '''
  if system == 'Windows':
    try:
      if not ctypes.windll.shell32.IsUserAnAdmin():  
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
        exit(0)
    except Exception as ex:
      print_color(f'\n[Err] {ex}', 'red')      
      exit(1)
  elif system == 'Linux':
    if os.getuid() != 0:
      print_color('\nPlease re-run the sniffer using sudo', 'red')
      exit(0)
class Validation:
  @staticmethod
  def validate_ip_address(ip_address):
    if ip_address != 'ALL':
      try:
        ipaddress.ip_address(ip_address) # try to convert str to ip address
        return ip_address
      except ValueError:
          raise argparse.ArgumentTypeError(f'Invalid IP address: {ip_address}')
    return 'ALL'
  
  @staticmethod
  def validate_num_packets(count):
      if not count or int(count) <= 0:
          raise argparse.ArgumentTypeError('Number of packets must be a positive integer (>= 0)!')
      return int(count)
    
  @staticmethod  
  def validate_protocol(protocol):
    if protocol != 'ALL':
      if protocol.upper() in ['TCP', 'UDP', 'ICMP']:
        return protocol.upper()
      else:
        raise argparse.ArgumentTypeError(f'Incorrect protocol! {protocol} is not TCP, UDP or ICMP!')
    return protocol
  
  @staticmethod  
  def validate_interface(interface_name):
    interface = next((intrfc for intrfc in get_interfaces() if intrfc['name'] == interface_name), None)
    if not interface:
      raise argparse.ArgumentTypeError(f'Interface {interface_name} not found!')
    return interface
  
class ArgumentParser(argparse.ArgumentParser):
  def print_help(self):
    print_logo() # print logo when printing helps
    super().print_help()
    print('\n\n')

def parse_args() -> argparse.Namespace:
  '''
  Parse command line arguments
  '''
  parser = ArgumentParser(
    description='packet sniffer by d00m_r34p3r',
    formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=56)
  )
  parser.add_argument( 
    '-I', '--interactive',
    action='store_true',
    help='interactive mode for settings'
  )
  parser.add_argument(
    '-i', '--interface',
    metavar='interface',
    type=Validation.validate_interface,
    help='interface to listen on'
  )
  parser.add_argument(
    '-p', '--protocol',
    metavar='protocol',
    type=Validation.validate_protocol,
    default='ALL',
    help='protocol to filter by (tcp, udp, icmp)'
  )
  parser.add_argument(
    '-ip', '--ip-address',
    metavar='ip_address',
    type=Validation.validate_ip_address,
    default='ALL',
    help='ip address to filter by'
  )
  parser.add_argument(
    '-r', '--raw',
    action='store_true',
    help='output packet contents in raw format'
  )
  parser.add_argument(
    '-hd', '--header',
    action='store_true',
    help='output header'
  )
  parser.add_argument(
    '-v','--verbose',
    action='store_true',
    help='print more information about packets'
  )
  parser.add_argument(
    '-s', '--save',
    metavar='filename',
    type=str,
    help='save packets to the specified file with .pcap extension. If file is not exist then create a new'
  )
  parser.add_argument(
    '-g','--graphics',
    action='store_true',
    help='draw graphics with statistics after sniffing (don\'t close window with sniffer)'
  )
  parser.add_argument(
    '-q','--quiet',
    action='store_true',
    help='don\'t show packets'
  )
  parser.add_argument(
    '-c','--count',
    type=Validation.validate_num_packets,
    metavar='N',
    help='number of packets to capture'
  )
  
  return parser.parse_args()

def get_interfaces() -> list:
  '''
  Get list of interfaces
  '''
  available_interfaces = []
  interfaces = ifaddr.get_adapters()

  for adapter in interfaces:
    interface = {}
    interface['name'] = adapter.nice_name
    interface['ip'] = adapter.ips[1].ip
    interface['mac'] = adapter.ips[0].ip[0]
    available_interfaces.append(interface)

  return available_interfaces

def print_table_with_interfaces(interfaces) -> None:
  '''
  Print table of interfaces
  '''
  table = PrettyTable()
  table.field_names = ["#", "Interface", "Ip"]
  for i, interface in enumerate(interfaces):
    table.add_row([i+1, interface['name'], interface['ip']])
  print(table)

def print_color(text, color=None) -> None:
  '''
  Print color text
  '''
  if color:
    color_obj = getattr(Fore, color.upper(), None)
    if color_obj:
      print(color_obj + text + Style.RESET_ALL)
      return
  print(text)  
  
def print_logo() -> None:
  print(Fore.GREEN + 
          ' _____           _        _   _____                           _                  \n'
          '|  __ \         | |      | | |_   _|                         | |                 \n'
          '| |__) |_ _  ___| | _____| |_  | |  _ __  ___ _ __   ___  ___| |_ ___  _ __      \n'
          '|  ___/ _` |/ __| |/ / _ \ __| | | | \'_ \/ __| \'_ \ / _ \/ __| __/ _ \| \'__|  \n'
          '| |  | (_| | (__|   <  __/ |_ _| |_| | | \__ \ |_) |  __/ (__| || (_) | |        \n'
          '|_|   \__,_|\___|_|\_\___|\__|_____|_| |_|___/ .__/ \___|\___|\__\___/|_|        \n'
          '                                             | |                                 \n'
          '                                             |_|                                 \n'
        + Style.RESET_ALL)

class Packet:
  '''
  Class for packet parsing
  '''
  def __init__(self, buff, src_ip=None, dst_ip=None, ip_version=None, ip_protocol_num=None):
    # Parse the packet header
    header = struct.unpack('<BBHHHBBH4s4s', buff)  # ipv4 header, add ipv6 header in future versions  
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
              
   
  def hexdump(packet) -> None:
    hex_data = ' '.join(f'{byte:02x}' for byte in packet)
    ascii_data = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in packet)
    lines = [hex_data[i:i+48] for i in range(0, len(hex_data), 48)]
    for line in lines:
        print(line)
    print(ascii_data)
   
def choose_interface(interfaces):
  '''
  Select the interface to sniff on
  '''
  print(f'[*] Available interfaces, enter a number between 1 and {len(interfaces)}:')
  print_table_with_interfaces(interfaces)
  while True:
    try:
        choice = int(input('\nEnter number of interface: '))
        if choice < 1 or choice > len(interfaces):
            raise ValueError
        break
    except KeyboardInterrupt:
      print('\nExiting...')
      exit(0)
    except ValueError:
      print_color('[Err] Incorrect number, try again!', 'yellow')
        
  return interfaces[choice-1]

def choose_protocol():
  '''
  Select the protocol to filter packets on
  '''
  protocols = ['TCP', 'UDP', 'ICMP', 'ALL']
  print('Available protocols:')
  print('1. TCP\n2. UDP\n3. ICMP\n4. ALL\n')
  while True:
    try:
        choice = int(input('\nEnter the number of the protocol to filter on: '))
        if choice < 1 or choice > len(protocols):
            raise ValueError
        break
    except KeyboardInterrupt:
      print('\nExiting...')
      exit(0)
    except ValueError:
      print_color('[Err] Incorrect number, try again!', 'yellow')
      
  return protocols[int(choice) - 1]

def get_sniffer_socket(system, interface) -> socket:
  '''
  Returns a socket for sniffing
  '''
  if system == 'Windows':
    sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer_socket.bind((interface['ip'], 0))
    sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) 
        
  elif system == 'Linux':
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer_socket.bind((interface['name'], 0))

  return sniffer_socket

def parse_packet(packet_data, raw, header) -> None:
  '''
  Parse a captured packet
  '''
  print('\n')
  if raw:
    print(packet_data)
  else:
    if header:
      print_color('Header:', 'yellow')
      print(packet_data[:14])
    print_color('Data:', 'yellow')
    print(packet_data[14:])

def get_unique_filename(filename):
  timestamp = datetime.datetime.now().strftime("%d%m%Y")
  counter = 1
  
  while os.path.exists('dumps/' + filename):
    filename = f"sniffing_{timestamp}({counter}).pcap"
    counter += 1
    
  return filename

class SniffingStatistics:
  def __init__(self):
    self.connection_activity = {}
    self.packets_statistics = {}
    self.packet_count = 0
    self.need_to_print = False

  def update_activity(self, src_ip, dst_ip):
    connection = (src_ip, dst_ip)

    if connection in self.connection_activity:
      self.connection_activity[connection] += 1
    else:
      self.connection_activity[connection] = 1

  def get_activity(self):
    return self.connection_activity.items()
    
  def create_thread(self):
    self.need_to_print = True
    update_thread = threading.Thread(target=self.update_packet_count)
    update_thread.daemon = True
    return update_thread
    
  def update_packet_count(self):
    while self.need_to_print:
      print(f'Total packets captured: {self.packet_count}', end='\r')
      time.sleep(1)
        
def main():
  args = parse_args() # get args and print help for sniffer if necessary

  system = platform.system() # we need to run as admin to create sockets
  run_as_admin(system) 
  
  init() #for colorama
  print_logo() # print logo
     
  interfaces = get_interfaces() # get net interfaces
  
  sniffing_stat = SniffingStatistics()
  
  if args.ip_address:
    print_color(f'\n[*] Provided IP address: {args.ip_address}\n', 'green')
  
  if not args.interactive and not args.interface:
    print_color('[Err] You must specify an interface or use interactive mode!', 'red')
    exit(0)
  
  if args.interactive:
    interface = choose_interface(interfaces)
    print(f"[*] Your choice: {interface['name']}\n")

    protocol = choose_protocol()
    print(f"[*] Your choice: {protocol}\n")
      
  while True:
    try:
      sniffer_socket = get_sniffer_socket(system, interface)
      break
    except Exception as ex:
      print_color(f'\n[Err] {ex}\nTry again with another interface!\n', 'yellow')
      if args.interactive:
        interface = choose_interface(interfaces)
      else:
        exit(0)
      
  filename = args.save
  if filename:
    filename +='.pcap'
    filename = get_unique_filename(filename)
      
    try:
      pcap_file = open('dumps/' + filename, 'wb')
      logging.info(f'Output file: {filename}')
    except IOError:
      print_color(f'[Err] Unable to open/create file {filename} in directory dumps', 'red')
      exit(0)

    pcap_writer = dpkt.pcap.Writer(pcap_file)

  print_color(f"\n[*] Sniffing started on interface {interface['name']}\nTo stop sniffing use Ctrl + c\n", 'green') 
  
  time.sleep(0.5)
  
  start_time = datetime.datetime.now()
  protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}
  
  if args.quiet:
    sniffing_stat.create_thread().start()
  
  while True:
    try:  
      raw_packet, address = sniffer_socket.recvfrom(65535)
      
      if len(raw_packet) < 20:
        continue
      
      filtered_ip_version = None
      filtered_ip_protocol_num = None
      filtered_src_ip = None
      filtered_dst_ip = None

      if args.ip_address != 'ALL' or protocol != 'ALL':
        ip_header = raw_packet[0:20]
        
        if args.ip_address != 'ALL':
          src_ip = socket.inet_ntoa(ip_header[12:16])
          dst_ip = socket.inet_ntoa(ip_header[16:20])
          
          if args.ip_address not in (src_ip, dst_ip):
            continue
          
          filtered_src_ip = src_ip
          filtered_dst_ip = dst_ip
          
        if protocol != 'ALL':
          # get from header version and protocol   
          ip_version = struct.unpack('!B', ip_header[0:1])[0] >> 4  
          ip_protocol_num = struct.unpack('!B', ip_header[9:10])[0] 
          
          if protocol != protocol_map[ip_protocol_num]:  
            continue
          
          filtered_ip_version = ip_version
          filtered_ip_protocol_num = ip_protocol_num
          
      # Process the packet
      sniffing_stat.packet_count += 1
      
      packet = Packet(raw_packet[0:20], filtered_ip_version, filtered_ip_protocol_num, filtered_src_ip, filtered_dst_ip)
      packet.print()
      
      if filename:
         pcap_writer.writepkt(raw_packet)
         
      if args.count:
        if sniffing_stat.packet_count == args.count:
          raise KeyboardInterrupt
      
    except KeyboardInterrupt:
      print('\n\nSniffing complete...')
      end_time = datetime.datetime.now()
      print(f'Total sniffing time: {end_time - start_time}')
      print(f'Total packets captured {sniffing_stat.packet_count}')
      if system == 'Windows':
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      break
    
    except Exception as ex:
      print_color(f'\n[Err] {ex}', 'red')
      logging.error(f'[Err] {ex}')
      break
    
  sniffing_stat.need_to_print = False
  if filename:
    print(f'Packets captured into {filename}, directory dumps')
    pcap_file.close()  
    
  input("\nPress Enter to continue...")  
  
if __name__ == '__main__':
  logging.basicConfig(level=logging.ERROR, filename=f'logs/sniffer_errors_{datetime.datetime.now().strftime("%d%m%Y")}.log',filemode='a')
  main()


