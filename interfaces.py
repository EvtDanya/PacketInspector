import ifaddr
import socket 
from print import *

def get_interfaces() -> list:
  '''
  Get list of interfaces
  '''
  available_interfaces = []
  interfaces = ifaddr.get_adapters()
  
  for adapter in interfaces:
    if hasattr(adapter, 'ips') and adapter.ips and hasattr(adapter.ips[0], 'ip'):
      interface = {
        'name': adapter.nice_name if hasattr(adapter, 'nice_name') and adapter.nice_name else 'Unknown',
        'ip': adapter.ips[0].ip
      }
      available_interfaces.append(interface)

  return available_interfaces

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
  print('1. TCP\n2. UDP\n3. ICMP\n4. ALL')
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