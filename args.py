import argparse
import ipaddress
from print import print_logo
from interfaces import get_interfaces

class Validation:
  '''
  Class for args validation
  '''
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
    '--ip-address',
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
    '-H', '--header',
    action='store_true',
    help='output header'
  )
  parser.add_argument(
    '-S','--show-payload',
    action='store_true',
    help='print payload of packets in hex and ascii format'
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
