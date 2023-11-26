<<<<<<< HEAD
import threading
import time

class SniffingStatistics:
  '''
  Class for sniffing stat(stat for graphics too)
  '''
  def __init__(self):
    self.connection_activity = {}
    self.ip_activity = {}
    self.packets_statistics = {'TCP':0, 'UDP':0, 'ICMP':0}
    
    self.packet_count = 0
    self.need_to_print = False

  def update_activity(self, src_ip, dst_ip) -> None:
    connection = (str(src_ip), str(dst_ip))

    self.connection_activity[connection] = self.connection_activity.get(connection, 0) + 1

    self.ip_activity[str(src_ip)] = self.ip_activity.get(str(src_ip), 0) + 1
    self.ip_activity[str(dst_ip)] = self.ip_activity.get(str(dst_ip), 0) + 1
    
  def update_packets_statistics(self, protocol) -> None:
    self.packets_statistics[protocol] = self.packets_statistics.get(protocol, 0) + 1
    
  def get_top_activity(self, activity, n=10) -> list:
    sorted_activity = sorted(activity.items(), key=lambda x: x[1], reverse=True)
    top_activity = sorted_activity[:n]
    return top_activity  
  
  def create_thread(self) -> threading.Thread:
    self.need_to_print = True
    update_thread = threading.Thread(target=self.update_packet_count)
    update_thread.daemon = True
    return update_thread
    
  def update_packet_count(self) -> None:
    while self.need_to_print:
      print(f'Total packets captured: {self.packet_count}', end='\r')
      time.sleep(1)
=======
import threading
import time

class SniffingStatistics:
  '''
  Class for sniffing stat(stat for graphics too)
  '''
  def __init__(self):
    self.connection_activity = {}
    self.ip_activity = {}
    self.packets_statistics = {'TCP':0, 'UDP':0, 'ICMP':0}
    
    self.packet_count = 0
    self.need_to_print = False

  def update_activity(self, src_ip, dst_ip) -> None:
    connection = (str(src_ip), str(dst_ip))

    self.connection_activity[connection] = self.connection_activity.get(connection, 0) + 1

    self.ip_activity[str(src_ip)] = self.ip_activity.get(str(src_ip), 0) + 1
    self.ip_activity[str(dst_ip)] = self.ip_activity.get(str(dst_ip), 0) + 1
    
  def update_packets_statistics(self, protocol) -> None:
    self.packets_statistics[protocol] = self.packets_statistics.get(protocol, 0) + 1
    
  def get_top_activity(self, activity, n=10) -> list:
    sorted_activity = sorted(activity.items(), key=lambda x: x[1], reverse=True)
    top_activity = sorted_activity[:n]
    return top_activity  
  
  def create_thread(self) -> threading.Thread:
    self.need_to_print = True
    update_thread = threading.Thread(target=self.update_packet_count)
    update_thread.daemon = True
    return update_thread
    
  def update_packet_count(self) -> None:
    while self.need_to_print:
      print(f'Total packets captured: {self.packet_count}', end='\r')
      time.sleep(1)
>>>>>>> 1816e615cdd3890e6bc432071a30d5bb06757eae
        