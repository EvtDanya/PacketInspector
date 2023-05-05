import ifaddr

interfaces = ifaddr.get_adapters()

print("Доступные интерфейсы:")
for i, interface in enumerate(interfaces):
    print(f"{i+1}: Name: {interface.nice_name}, IP-address: {interface.ips[1].ip}, Mac-address: {interface.ips[0].ip[0]}")

while True:
    try:
        choice = int(input("\nВведите номер интерфейса: "))
        if choice < 1 or choice > len(interfaces):
            raise ValueError
        break
    except ValueError:
        print("Ошибка: Введите корректный номер интерфейса")

interface_name = interfaces[choice-1].nice_name
print(f"Выбран интерфейс: {interface_name}")