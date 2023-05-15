import socket 
import argparse
import platform
import ifaddr
from colorama import init, Fore, Style
from prettytable import PrettyTable
import datetime
import logging
import pcapfile

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
  parser.add_argument('-o', '--output', metavar='filename', type=str, help='Output file name')

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
  table = PrettyTable()
  table.field_names = ["#", "Interface", "Ip"]
  for i, interface in enumerate(interfaces):
    table.add_row([i+1, interface['name'], interface['ip']])
  print(table)

def print_color(text, color=None):
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
  
def main(): 
  init()
  print_logo()
    
  args = parse_args()  
  system = platform.system()
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
      protocol = input('Enter protocol to sniff for (TCP, UDP, ICMP): ')
      if protocol.upper() in ['TCP', 'UDP', 'ICMP']:
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

  try:
    sniffer_socket = get_sniffer_socket(system, interface)
  except KeyboardInterrupt:
    print('\nExiting...')
    exit(0)
  except Exception as ex:
    print_color(f'\n[Err] {ex}\nTry again with another interface!\n', 'yellow')
    if args.interactive:
      interface = choose_interface(interfaces)
    else:
      exit(1)
      
  output_file = args.output
  if output_file:
    try:
      pcap_file = open(args.output, 'wb')
      logging.info(f"Output file: {args.output}")
    except IOError:
      print_color(f'[Err] Unable to open file {args.output}', 'red')
      exit(0)
      
  print_color(f"\n[*] Sniffing started on interface {interface['name']}\n", 'green')    
  start_time = datetime.datetime.now()
  while True:
    try:
      print(sniffer_socket.recvfrom(65535))
    except KeyboardInterrupt:
      print('\nExiting...')
      end_time = datetime.datetime.now()
      print("Total sniffing time:", end_time - start_time) # перенести вывод, добавить статистику по пакетам
      if system == 'Windows':
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      exit(0)
    except socket.error as e:
      print_color(f"[Err] Error: {e}", 'red')
      logging.error(f"[Err] Error: {e}")
    finally:
      sniffer_socket.close()
      if args.output:
        pcap_file.close()

if __name__ == '__main__':
  logging.basicConfig(level=logging.ERROR, filename="sniffer.log",filemode="a")
  main()


