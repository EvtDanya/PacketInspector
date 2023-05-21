# PacketInspector
### Packet sniffing in python

### Installation
To install dependencies for this program you can use scripts:  
 • for unix systems - install_dependencies.sh;  
 • for windows - install_dependencies.bat.  

### About
You can start PacketInspector with -h argument to see all opportunities.  
![alt text](https://github.com/EvtDanya/Packet_Inspector/blob/main/print_help.png)

### Examples
You can start sniffer with "-I -H -S -s test" arguments to use interactive mode, print more information about packets and save them into file test.pcap.  
At start you can choose interface to sniff on and protocol to filter packets.  
![alt text](https://github.com/EvtDanya/Packet_Inspector/blob/main/example.png)  
After you will see packets and after sniffing packets will be available in file with unique name (because name test is already in use) in directory dumps.  
![alt text](https://github.com/EvtDanya/Packet_Inspector/blob/main/example_of_packets.png)  
You can open pcap file with Wireshark for example.  
![alt text](https://github.com/EvtDanya/Packet_Inspector/blob/main/saved_pcaps.png)  


