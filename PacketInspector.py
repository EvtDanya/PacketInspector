import socket 
import argparse
import platform
import ifaddr
import json

def parse_args():
  '''
  Parse command line arguments
  '''
  parser = argparse.ArgumentParser(description='packet sniffer with python by d00m_r34p3r')
  parser.add_argument('-p', '--protocol', metavar='protocol',  type=str, default='tcp', help='protocol to filter by (tcp, udp, icmp)')
  parser.add_argument('-i', '--interface', metavar='interface', type=str, help='interface to listen on')
  parser.add_argument('-r', '--raw', action='store_true', help='output packet contents in raw format')
  parser.add_argument('-hd', '--header', action='store_true', help='output header')
  parser.add_argument('-I', '--interactive', action='store_true', help='interactive mode for settings')

  return parser.parse_args()

def get_interfaces():
  '''
  Get list of interfaces
  '''
  list_of_interfaces = []
  interfaces = ifaddr.get_adapters()

  for interface in interfaces:
    interface_for_list = {}
    interface_for_list['name'] = interface.nice_name
    interface_for_list['ip'] = interface.ips[1].ip
    interface_for_list['mac'] = interface.ips[0].ip[0]
    list_of_interfaces.append(interface_for_list)

  return list_of_interfaces

interfaces = get_interfaces()

def print_logo():
  print(
          ' _____           _        _   _____                           _                  \n'
          '|  __ \         | |      | | |_   _|                         | |                 \n'
          '| |__) |_ _  ___| | _____| |_  | |  _ __  ___ _ __   ___  ___| |_ ___  _ __      \n'
          '|  ___/ _` |/ __| |/ / _ \ __| | | | \'_ \/ __| \'_ \ / _ \/ __| __/ _ \| \'__|  \n'
          '| |  | (_| | (__|   <  __/ |_ _| |_| | | \__ \ |_) |  __/ (__| || (_) | |        \n'
          '|_|   \__,_|\___|_|\_\___|\__|_____|_| |_|___/ .__/ \___|\___|\__\___/|_|        \n'
          '                                             | |                                 \n'
          '                                             |_|                                 \n'
        )
  
def choose_interface():
  '''
  Select the interface to sniff on
  '''
  print('Available interfaces, choose one of them:')
  for i, interface in enumerate(interfaces):
    print(f"{i+1}: {interface['name']}, {interface['ip']}")
  while True:
    try:
        choice = int(input('\nEnter number of interface: '))
        if choice < 1 or choice > len(interfaces):
            raise ValueError
        break
    except ValueError:
      print("Incorrect number, try again!")
        
  return interfaces[choice-1]['name']
  
def main(): 
  print_logo()
    
  args = parse_args()  
  system = platform.system()
  
  if not args.interactive and not args.interface:
    print('You must specify an interface or use interactive mode!')
    exit(0)
  
  if args.interactive:
    interface = choose_interface()
    print(f"Your choice: {interface}\n")
  
  else:
    interface = next((x for x in interfaces if x['name'] == args.interface), None)
    if interface is None:
      print(f"Interface {args.interface} not found")
      exit(0) 
  
  if not args.protocol and not args.interactive:
    print('You must specify the protocol or use interactive mode!')
    exit(0)
    
  if args.interactive:
    while True:
      protocol = input("Enter protocol to sniff for (TCP, UDP, ICMP): ")
      if protocol.upper() in ['TCP', 'UDP', 'ICMP']:
        protocol = protocol.upper()
        break
      else:
        print('Invalid protocol! Try again\n')
  else:
    if args.protocol.upper() in ['TCP', 'UDP', 'ICMP']:
      protocol = args.protocol.upper()
    else:
      print(f'Incorrect protocol! {args.protocol} is not TCP, UDP or ICMP')
      exit(0)  

  
  
  try:
    if system == "Windows":
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((interface, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
    elif system == "Linux":
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((interface, 0))
  except Exception as ex:
    print(f'\n[*] {ex}\nTry again with another interface!\n')
    if args.interactive:
      choose_interface()
    else:
      exit(1)
    
  while True:
      packet, addr = sock.recvfrom(65535)

if __name__ == "__main__":
  main()


