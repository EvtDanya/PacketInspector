import matplotlib.pyplot as plt

def draw_statistics(data, xlabel, ylabel, title, position):
    '''
    Draw statistics with the given parameters
    '''
    labels = [str(item[0]) for item in data]
    values = [item[1] for item in data]

    ax = plt.subplot(position)
    ax.bar(labels, values)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)

def show_statistics(sniffing_stat):
    '''
    Displays a window with statistics graphs
    '''
    plt.figure(num='Packet Inspector statistics', figsize=(10, 6)) 

    draw_statistics(
        sniffing_stat.get_top_activity(sniffing_stat.connection_activity, 6),
        'Connection',
        'Amount of packets',
        'Connections activity statistics',
        211
    )
    
    draw_statistics(
        sniffing_stat.get_top_activity(sniffing_stat.ip_activity, 4),
        'IP Address',
        'Amount of packets',
        'IP Address statistics',
        223
    )
    
    draw_statistics(
        sniffing_stat.get_top_activity(sniffing_stat.packets_statistics, 4),
        'Protocol',
        'Amount of packets',
        'Protocol statistics',
        224
    )

    plt.tight_layout()  
    plt.show()