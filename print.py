from colorama import Fore, Style
from prettytable import PrettyTable

def print_color(text, color=None) -> None:
  '''
  Print color text
  '''
  if color:
    color_obj = getattr(Fore, color.upper(), None)
    if color_obj:
      print(color_obj + text + Style.RESET_ALL)
      return
  print(text)  
  
def print_logo() -> None:
  print(Fore.GREEN + 
          ' _____           _        _   _____                           _                  \n'
          '|  __ \         | |      | | |_   _|                         | |                 \n'
          '| |__) |_ _  ___| | _____| |_  | |  _ __  ___ _ __   ___  ___| |_ ___  _ __      \n'
          '|  ___/ _` |/ __| |/ / _ \ __| | | | \'_ \/ __| \'_ \ / _ \/ __| __/ _ \| \'__|  \n'
          '| |  | (_| | (__|   <  __/ |_ _| |_| | | \__ \ |_) |  __/ (__| || (_) | |        \n'
          '|_|   \__,_|\___|_|\_\___|\__|_____|_| |_|___/ .__/ \___|\___|\__\___/|_|        \n'
          '                                             | |                                 \n'
          '                                             |_|                                 \n'
        + Style.RESET_ALL)
 
def print_table_with_interfaces(interfaces) -> None:
  '''
  Print table of interfaces
  '''
  table = PrettyTable()
  table.field_names = ['#', 'Interface', 'Ip']
  for i, interface in enumerate(interfaces):
    table.add_row([i+1, interface['name'], interface['ip']])
  print(table)
 