import matplotlib.pyplot as plt
import sys

def draw():
    ip_statistics = {
        'TCP': 100,
        'UDP': 50,
        'ICMP': 20
    }
    
    labels = ip_statistics.keys()
    values = ip_statistics.values()
    
    fig, ax = plt.subplots()
    ax.bar(labels, values)
    
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Packets count')
    ax.set_title('Sniffing statistics')
    
    plt.show()
    