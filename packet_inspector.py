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
    except Exception as e:
      print_color(f'\n[Err] {e}', 'red')      
      exit(1)
  elif system == 'Linux':
    if os.getuid() != 0:
      print_color('\nPlease re-run the sniffer using sudo', 'red')
      exit(0)

def validate_ip_address(ip_address):
  if ip_address != 'ALL':
    try:
      socket.inet_aton(ip_address) # try to convert str to ip address
      return ip_address
    except socket.error:
        raise argparse.ArgumentTypeError(f'Invalid IP address: {ip_address}')
  return 'ALL'

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
    type=str,
    help='interface to listen on'
  )
  parser.add_argument(
    '-p', '--protocol',
    metavar='protocol',
    type=str,
    default='ALL',
    help='protocol to filter by (tcp, udp, icmp)'
  )
  parser.add_argument(
    '-ip', '--ip-address',
    metavar='ip_address',
    type=validate_ip_address,
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
    '-o', '--output',
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
    '-c','--clear-output',
    action='store_true',
    help='don\'t show packets'
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
  if color is not None:
    color_obj = getattr(Fore, color.upper(), None)
    if color_obj is not None:
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
    self.ver = ip_version
    self.src_address = ipaddress.ip_address(src_ip)
    self.dst_address = ipaddress.ip_address(dst_ip)
    self.buff = buff

    if self.ver is None:
      self.ver = self.src_address.version

    self.protocol_num = ip_protocol_num
    if self.protocol_num is None:
        # Set protocol number based on IP version
        if self.ver == 4:
            self.protocol_num = socket.IPPROTO_IP
        elif self.ver == 6:
            self.protocol_num = socket.IPPROTO_IPV6
        else:
                raise ValueError(f'Unsupported IP version: {self.ver}')

        # Parse the packet header
    header = struct.unpack('<BBHHHBBH4s4s', buff)  # ipv4 header, add ipv6 header in future versions  
    self.ihl = header[0] & 0xF
    self.tos = header[1]
    self.len = header[2]
    self.id = header[3]
    self.offset = header[4]
    self.ttl = header[5]
    self.sum = header[7]        

   
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
  # for i, interface in enumerate(interfaces):
  #   print(f"{i+1}: {interface['name']}, {interface['ip']}")
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

def update_packet_count():
  global packet_count, need_to_print
  while need_to_print:
    print(f'Total packets captured: {packet_count}', end='\r')
    time.sleep(1)

packet_count = 0
need_to_print = False

def main():
  args = parse_args() # get args and print help for sniffer if necessary

  system = platform.system() # we need to run as admin to create sockets
  run_as_admin(system) 
  
  init() #for colorama
  print_logo() # print logo
     
  interfaces = get_interfaces() # get net interfaces
  global packet_count, need_to_print
  
  if args.ip_address:
    print_color(f'\n[*] Provided IP address: {args.ip_address}\n', 'green')
  
  if not args.interactive and not args.interface:
    print_color('[Err] You must specify an interface or use interactive mode!', 'red')
    exit(0)
  
  if args.interactive:
    interface = choose_interface(interfaces)
    print(f"[*] Your choice: {interface['name']}\n")
  
  else:
    interface = next((x for x in interfaces if x['name'] == args.interface), None)
    if interface is None:
      print_color(f'[Err] Interface {args.interface} not found', 'red')
      exit(0) 
      
  
  if not args.protocol and not args.interactive:
    print_color('[Err] You must specify the protocol or use interactive mode!', 'red')
    exit(0)
    
  if args.interactive:
    while True:
      protocol = input('Enter protocol to sniff for (TCP, UDP, ICMP, ALL): ')
      if protocol.upper() in ['TCP', 'UDP', 'ICMP', 'ALL']:
        protocol = protocol.upper()
        break
      else:
        print_color('[Err] Invalid protocol! Try again\n', 'yellow')
  else:
    if args.protocol.upper() in ['TCP', 'UDP', 'ICMP']:
      protocol = args.protocol.upper()
    else:
      print_color(f'[Err] Incorrect protocol! {args.protocol} is not TCP, UDP or ICMP','yellow')
      exit(0)  
      
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
      
  output_file = args.output
  if output_file:
    output_file +='.pcap'
    try:
      pcap_file = open(args.output, 'a')
      logging.info(f'Output file: {args.output}')
    except IOError:
      print_color(f'[Err] Unable to open file {args.output}', 'red')
      exit(0)
      
  print_color(f"\n[*] Sniffing started on interface {interface['name']}\nTo stop sniffing use Ctrl + c\n", 'green') 
  
  time.sleep(0.5)
  
  start_time = datetime.datetime.now()
  protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}
  
  if args.clear_output:
    need_to_print = True
    update_thread = threading.Thread(target=update_packet_count)
    update_thread.daemon = True
    update_thread.start()
  
  while True:
    try:  
      raw_packet, address = sniffer_socket.recvfrom(65535)
      
      if len(raw_packet) < 20:
        continue
      
      packet_count += 1
      
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
          ip_version, ip_protocol_num = struct.unpack('!BB', ip_header[0:2])
          ip_version >>= 4
          
          if protocol != protocol_map[ip_protocol_num]:  
            continue
          
          filtered_ip_version = ip_version
          filtered_ip_protocol_num = ip_protocol_num
          
      # Process the packet
      packet = Packet(raw_packet[0:20], filtered_ip_version, filtered_ip_protocol_num, filtered_src_ip, filtered_dst_ip)
      
      if output_file:
        pcap_file.write(str(raw_packet))
      
    except KeyboardInterrupt:
      print('\nExiting...')
      end_time = datetime.datetime.now()
      print(f'Total sniffing time: {end_time - start_time}')
      print(f'Total packets captured {packet_count}')
      if system == 'Windows':
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      break
    
    except Exception as e:
      print_color(f'\n[Err] {e}', 'red')
      logging.error(f'[Err] {e}')
      break
    
  need_to_print = False  
  input("\nPress Enter to continue...")  
  if args.output:
    print(f'Packets captured into {args.output}.pcap')
    pcap_file.close()
    
if __name__ == '__main__':
  logging.basicConfig(level=logging.ERROR, filename='sniffer.log',filemode='a')
  main()

