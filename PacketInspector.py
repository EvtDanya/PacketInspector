import socket 
import argparse
import platform
import ifaddr

def parse_args():
  '''
  Parse command line arguments
  '''
  parser = argparse.ArgumentParser(description='packet sniffer with python by d00m_r34p3r')
  parser.add_argument('-p', '--protocol', metavar='protocol',  type=str, default='tcp', help='protocol to filter by (tcp, udp, icmp)')
  parser.add_argument('-i', '--interface', metavar='interface', type=str, help='interface to listen on')
  parser.add_argument('-r', '--raw', action='store_true', help='output packet contents in raw format')
  parser.add_argument('-hd', '--header', action='store_true', help='output header')
  parser.add_argument('--interactive', action='store_true', help='interactive mode for settings')

  return parser.parse_args()

def get_interfaces():
  list_of_interfaces = {}
  interfaces = ifaddr.get_adapters()

  for interface in interfaces:
    list_of_interfaces.update({f"{interface.nice_name}":f"IP-address: {interface.ips[1].ip}, Mac-address: {interface.ips[0].ip[0]}"})
  
  return list_of_interfaces

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
  interfaces = get_interfaces()
  print('Available interfaces, choose one of them:')
  for i, interface in enumerate(interfaces):
    print(f"{i+1}: {interface}, {interfaces[interface]}")
  while True:
    try:
        choice = int(input('\nEnter number of interface: '))
        if choice < 1 or choice > len(interfaces):
            raise ValueError
        break
    except ValueError:
      print("Incorrect number, try again!")
        
  return list(interfaces)[choice-1]
  
def main():   
  args = parse_args()  
  system = platform.system()
  
  if not args.interactive and not args.interface:
    print('You must specify an interface or use interactive mode!')
    exit(0)
  
  if args.interactive:
    interface = choose_interface()
    print(f"Your choice: {interface}\n")
  
  else: 
    interface = args.interface 
  
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
    print(f'[*] {ex}\nTry again with another interface!\n')
    if args.interactive:
      choose_interface()
    else:
      exit(1)
    
  while True:
      packet, addr = sock.recvfrom(65535)

if __name__ == "__main__":
  main()


