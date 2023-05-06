import socket
import struct

# Создаем сокет
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Бесконечный цикл для приема данных
while True:
    # Получаем данные
    data, addr = sock.recvfrom(65535)
    
    # Распознаем протокол
    ethertype = struct.unpack("!H", data[12:14])[0]
    
    if ethertype == 0x0800: # IPv4
        # Выводим данные на экран
        print(data)
