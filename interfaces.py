import ifaddr

interfaces = ifaddr.get_adapters()

print("Доступные интерфейсы:")
for i, interface in enumerate(interfaces):
    print(f"{i+1}: {interface.nice_name} {interface.name} {interface.ips}")

while True:
    try:
        choice = int(input("\nВведите номер интерфейса: "))
        if choice < 1 or choice > len(interfaces):
            raise ValueError
        break
    except ValueError:
        print("Ошибка: Введите корректный номер интерфейса")

interface_name = interfaces[choice-1].name
print(f"Выбран интерфейс: {interface_name}")