import socket
import struct
# Создаем сокет типа AF_PACKET для получения всех пакетов сетевого уровня
sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
# Бесконечный цикл для получения и обработки пакетов
while True:
    # Получаем данные из сокета
    packet_data, address = sniffer_socket.recvfrom(65536)
    # Извлекаем Ethernet заголовок
    eth_header = packet_data[:14]
    eth_header_unpack = struct.unpack("!6s6sH", eth_header)
    dst_mac = eth_header_unpack[0].hex()
    src_mac = eth_header_unpack[1].hex()
    eth_type = socket.ntohs(eth_header_unpack[2])
    # Выводим информацию об Ethernet заголовке
    print("Destination MAC: {}, Source MAC: {}, Type: {}".format(dst_mac, src_mac, eth_type))
    # Если это IP-пакет, то извлекаем его заголовок
    if eth_type == 0x0800:
        ip_header = packet_data[14:34]
        ip_header_unpack = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version = ip_header_unpack[0] >> 4
        ihl = ip_header_unpack[0] & 0xF
        ttl = ip_header_unpack[5]
        protocol = ip_header_unpack[6]
        src_ip = socket.inet_ntoa(ip_header_unpack[8])
        dst_ip = socket.inet_ntoa(ip_header_unpack[9])
        # Выводим информацию об IP заголовке
        print("Version: {}, IHL: {}, TTL: {}, Protocol: {}, Source IP: {}, Destination IP: {}".format(version, ihl, ttl, protocol, src_ip, dst_ip))
        # Если это TCP-пакет, то извлекаем его заголовок
        if protocol == 6:
            tcp_header = packet_data[34:54]
            tcp_header_unpack = struct.unpack("!HHLLBBHHH", tcp_header)
            src_port = tcp_header_unpack[0]
            dst_port = tcp_header_unpack[1]
            sequence_number = tcp_header_unpack[2]
            ack_number = tcp_header_unpack[3]
            data_offset = tcp_header_unpack[4] >> 4
            flags = tcp_header_unpack[5]
            window_size = tcp_header_unpack[6]
            checksum = tcp_header_unpack[7]
            urgent_pointer = tcp_header_unpack[8]
            # Выводим информацию о TCP заголовке
            print("Source Port: {}, Destination Port: {}, Sequence Number: {}, Acknowledgment Number: {}, Data Offset: {}, Flags: {}, Window Size: {}, Checksum: {}, Urgent Pointer: {}".format(src_port, dst_port, sequence_number, ack_number, data_offset, flags, window_size, checksum, urgent_pointer))
    # Другие протоколы (например, UDP) можно обработать аналогично