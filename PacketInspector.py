import socket 
import argparse

parser = argparse.ArgumentParser(description='packet sniffer with python by d00m_r34p3r')
parser.add_argument('-p', '--protocol', type=str, default='tcp', help='protocol to filter by (tcp, udp, icmp)')
parser.add_argument('-i', '--interface', type=str, default='eth0', help='interface to listen on')
parser.add_argument('-r', '--raw', action='store_true', help='output packet contents in raw format')
parser.add_argument('-hd', '--header', action='store_true', help='output header')


if __name__ == "__main__":
    print('\033[32m' +
          ' _____           _        _   _____                           _                  \n'
          '|  __ \         | |      | | |_   _|                         | |                 \n'
          '| |__) |_ _  ___| | _____| |_  | |  _ __  ___ _ __   ___  ___| |_ ___  _ __      \n'
          '|  ___/ _` |/ __| |/ / _ \ __| | | | \'_ \/ __| \'_ \ / _ \/ __| __/ _ \| \'__|  \n'
          '| |  | (_| | (__|   <  __/ |_ _| |_| | | \__ \ |_) |  __/ (__| || (_) | |        \n'
          '|_|   \__,_|\___|_|\_\___|\__|_____|_| |_|___/ .__/ \___|\___|\__\___/|_|        \n'
          '                                             | |                                 \n'
          '                                             |_|                                 \n'
          + '\033[0m'
        )
    
args = parser.parse_args()   
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
sock.bind((args.interface, 0)) 