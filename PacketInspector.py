import argparse
import platform

#pretty print
from colorama import init, Fore, Style
from prettytable import PrettyTable

import datetime
import logging

import ipaddress
import ifaddr
import socket 
import struct

# for running as admin
import ctypes
import sys
import os

def run_as_admin(system):
  '''
  Check if admin and run as admin if needed
  '''
  if system == 'Windows':
    try:
      if not ctypes.windll.shell32.IsUserAnAdmin():  
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, " ".join(sys.argv), None, 1)
        exit(0)
    except Exception as e:
      print_color(f'\n[Err] {e}', 'red')      
      exit(1)
  elif system == 'Linux':
    if os.getuid() != 0:
      print_color('\nPlease re-run the sniffer using sudo', 'red')
      exit(0)

def parse_args():
  '''
  Parse command line arguments
  '''
  parser = argparse.ArgumentParser(description='packet sniffer with python by d00m_r34p3r')
  parser.add_argument('-I', '--interactive', action='store_true', help='interactive mode for settings')
  parser.add_argument('-p', '--protocol', metavar='protocol',  type=str, default='tcp', help='protocol to filter by (tcp, udp, icmp)')
  parser.add_argument('-i', '--interface', metavar='interface', type=str, help='interface to listen on')
  parser.add_argument('-r', '--raw', action='store_true', help='output packet contents in raw format')
  parser.add_argument('-hd', '--header', action='store_true', help='output header')
  parser.add_argument('-o', '--output', metavar='filename', type=str, help='Save packages to the specified file (without extension). If file is not exist then create a new')

  return parser.parse_args()

def get_interfaces():
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

def print_table_with_interfaces(interfaces):
  '''
  Print table of interfaces
  '''
  table = PrettyTable()
  table.field_names = ["#", "Interface", "Ip"]
  for i, interface in enumerate(interfaces):
    table.add_row([i+1, interface['name'], interface['ip']])
  print(table)

def print_color(text, color=None):
  '''
  Print color text
  '''
  if color is not None:
    color_obj = getattr(Fore, color.upper(), None)
    if color_obj is not None:
      print(color_obj + text + Style.RESET_ALL)
      return
  print(text)  
  

def print_logo():
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

class IP:
  '''
  Class for packet parsing
  '''
  def __init__(self, buff=None):
    header = struct.unpack('<BBHHHBBH4s4s', buff) # ipv4 header, add ipv6 header in future versions
    self.ver 

  
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

def get_sniffer_socket(system, interface):
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

def parse_packet(packet_data, raw, header):
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

# def filter_packet(packet, filter):
#   '''
#   Filter a packet
#   '''
#   return True

def process_packet(packet):
  '''
  Process a packet
  ''' 
  return 

def main():
  system = platform.system()
  run_as_admin(system) 
  
  init()
  print_logo()
    
  args = parse_args()  
  interfaces = get_interfaces()
  
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
      logging.info(f"Output file: {args.output}")
    except IOError:
      print_color(f'[Err] Unable to open file {args.output}', 'red')
      exit(0)
      
  print_color(f"\n[*] Sniffing started on interface {interface['name']}", 'green')    
  packet_count = 0
  start_time = datetime.datetime.now()
  while True:
    try:
      raw_packet, address = sniffer_socket.recvfrom(65535)
      #фильтровать по айпи и по протоколу и по порту назначения
      packet_count += 1
      
      # Process the packet
      parse_packet(raw_packet, args.raw, args.header)

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
    
    except socket.error as e:
      print_color(f'\n[Err] {e}', 'red')
      logging.error(f'[Err] {e}')
      break
    
  if args.output:
    print(f'Packets captured into {args.output}.pcap')
    pcap_file.close()
      

if __name__ == '__main__':
  logging.basicConfig(level=logging.ERROR, filename='sniffer.log',filemode='a')
  main()


