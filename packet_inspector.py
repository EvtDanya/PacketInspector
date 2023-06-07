import platform

from colorama import init

import datetime
import logging

# for sniffing 
import struct
import time
import dpkt

# for running as admin
import ctypes
import sys
import os

from graphics import *
from args import *
from packet import *
from print import *
from interfaces import *
from sniffing_stat import *

def run_as_admin(system) -> None:
  '''
  Check if admin and run as admin if needed 
  '''
  if system == 'Windows':
    try:
      if not ctypes.windll.shell32.IsUserAnAdmin(): 
        arguments = ' '.join(['"{}"'.format(arg) for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, arguments, None, 1)
        exit(0)
    except Exception as ex:
      print_color(f'\n[Err] {ex}', 'red')
      logging.error(f'[Err] {ex}')
      input('\nPress Enter to continue...') 
      exit(1)
  elif system == 'Linux':
    if os.getuid() != 0:
      print_color('\nPlease re-run the sniffer using sudo', 'red')
      exit(0)
      
def get_unique_filename(filename) -> str:
  '''
  Get the unique filename
  '''
  timestamp = datetime.datetime.now().strftime('%d%m%Y')
  counter = 1
  
  while os.path.exists('dumps/' + filename):
    filename = f'sniffing_{timestamp}({counter}).pcap'
    counter += 1
    
  return filename

def main():
  args = parse_args() # get args and print help for sniffer if necessary
  
  system = platform.system() # we need to run as admin to create sockets
  run_as_admin(system) 
  
  init() #for colorama
  print_logo() # print logo
  
  interfaces = get_interfaces() # get net interfaces
  
  sniffing_stat = SniffingStatistics()
  
  if not args.interactive and not args.interface:
    print_color('[Err] You must specify an interface or use interactive mode!', 'red')
    input('\nPress Enter to continue...') 
    exit(0)
  
  if args.interface:
    interface = args.interface
    protocol = args.protocol
  
  if args.interactive:
    interface = choose_interface(interfaces)
    print(f"[*] Your choice: {interface['name']}\n")

    protocol = choose_protocol()
    print(f'[*] Your choice: {protocol}\n')
      
  while True:
    try:
      sniffer_socket = get_sniffer_socket(system, interface)
      break
    except Exception as ex:
      print_color(f'\n[Err] {ex}\nTry again with another interface!\n', 'red')
      logging.error(f'[Err] {ex}')
      if args.interactive:
        interface = choose_interface(interfaces)
      else:
        input('\nPress Enter to continue...') 
        exit(0)
      
  filename = args.save
  if filename:
    filename += '.pcap'
    filename = get_unique_filename(filename)
      
    try:
      pcap_file = open('dumps/' + filename, 'wb')
      logging.info(f'Output file: {filename}')
    except IOError:
      print_color(f'[Err] Unable to open/create file {filename} in directory dumps', 'red')
      input('\nPress Enter to continue...') 
      exit(0)

    pcap_writer = dpkt.pcap.Writer(pcap_file)
    
  if args.ip_address:
    print_color(f'\n[*] Provided IP address: {args.ip_address}\n', 'green')
    
  print_color(f"\n[*] Sniffing started on interface {interface['name']}\nTo stop sniffing use Ctrl + c\n", 'green') 
  
  time.sleep(0.5) # если большой поток пакетов в самом начале сниффинга будет, то пользователь не увидит как остановить сниффинг
  
  start_time = datetime.datetime.now()
  protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}
  
  if args.quiet:
    sniffing_stat.create_thread().start()
  
  while True:
    try:  
      raw_packet = sniffer_socket.recvfrom(65535)[0]
      timestamp = int(datetime.datetime.now().timestamp())
      
      ip_version = struct.unpack('!B', raw_packet[0:20][0:1])[0] >> 4  
      ip_protocol_num = struct.unpack('!B', raw_packet[0:20][9:10])[0] 
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
          try:
            if protocol != protocol_map[ip_protocol_num]:  
              continue
          except Exception:
            continue
          
      #process the packet
      sniffing_stat.packet_count += 1
      
      packet = PacketFactory.create_packet(system, raw_packet, filtered_src_ip, filtered_dst_ip, ip_version, ip_protocol_num, timestamp, args.raw, sniffing_stat.packet_count)
      
      #update stat
      if args.graphics:
        sniffing_stat.update_activity(packet.src_address, packet.dst_address)
        sniffing_stat.update_packets_statistics(packet.protocol)
      
      #print packet's data
      if not args.quiet:
        if args.header:
          packet.print_header()
        else:
          packet.print_less()
        if args.show_payload:
          packet.print_payload()
        
      if filename:
        pcap_writer.writepkt(packet.get_pcap_packet().pack())      
         
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
    
  if (args.graphics):
    show_statistics(sniffing_stat)
    
  if filename:
    print(f'Packets captured into file {filename} in directory dumps')
    pcap_file.close()  
    
  input('\nPress Enter to continue...')  
  
  
if __name__ == '__main__':
  #creating a log with the current date in its name
  logging.basicConfig(level=logging.DEBUG, filename=f"logs/sniffer_errors_{datetime.datetime.now().strftime('%d%m%Y')}.log", filemode='a', encoding='utf-8')
  main()


