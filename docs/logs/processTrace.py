from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt

node_wlan_sa = ['d8:3a:dd:34:b7:cd', 
                'd8:3a:dd:34:b8:d5', 
                'd8:3a:dd:e0:9c:d4', 
                'd8:3a:dd:e0:9f:f3', 
                'd8:3a:dd:96:7a:78', 
                'd8:3a:dd:96:6e:12']

node_colors = ['#0000ff', 
               '#ff2c2c',
               '#008000', 
               '#fd3db5', 
               '#ffde21', 
               '#00ffff']

tdma_round_len_ms = 300
offset = 35

def format_key(key):

    #drone1 -> Drone 1

    split_key = re.findall(r'[A-Za-z]+|\d+', key)

    new_key = split_key[0].capitalize() + ' ' + split_key[1]

    return new_key

def plot_packet(packet, relative_timestamp_ms):
    
    x = (relative_timestamp_ms + offset) % 300
    y = math.floor((relative_timestamp_ms + offset) / 300)

    #print(str(packet) + str((x, y)))

    #print(str(packet) + '---' + str(relative_timestamp_ms))

    return (x, y)

    

def process_pcap(file_path):

    count = 0
    data_points = dict()
    first_packet_time_ms = 0

    for packet in PcapReader(file_path):

        point = None
        label = None
        color = None
        name = None

        if packet.haslayer('Dot11'):

            dot11 = packet['Dot11']

            if dot11.type != 2:
                continue

            timestamp_ms = packet.time * 1000

            if not first_packet_time_ms:
                first_packet_time_ms = timestamp_ms

            relative_timestamp_ms = timestamp_ms - first_packet_time_ms

            if relative_timestamp_ms > 800075:

                wlan_source_address = dot11.addr2
                
                if wlan_source_address == node_wlan_sa[0]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone1'
                elif wlan_source_address == node_wlan_sa[1]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone2'
                elif wlan_source_address == node_wlan_sa[2]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone3'
                elif wlan_source_address == node_wlan_sa[3]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone4'
                elif wlan_source_address == node_wlan_sa[4]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone5'
                elif wlan_source_address == node_wlan_sa[5]:
                    point = plot_packet(packet, relative_timestamp_ms)
                    name = 'drone6'
                else:
                    continue

                if name not in data_points.keys():
                    data_points[name] = []

                data_points[name].append(point)

                if(count > 10000):
                    break

                count += 1
    
    sorted_keys = sorted(data_points.keys())
    index = 0


    for key in sorted_keys:

        points = data_points[key]

        x_points = [x for x, y in points]
        y_points = [y for x, y in points]
        
        plt.scatter(x_points, y_points, label=format_key(key), marker='s', color=node_colors[index], s=30, edgecolors='black')

        index+=1

    print('Done.')


if __name__ == '__main__':

    process_pcap('./tdma-50ms-slot-tests/six-node-sync-progression/trace_new.pcapng.gz')

    #process_pcap('./tdma-tests/six-node-throughput-udp/50ms-six-node-udp.pcapng.gz')

    plt.legend(loc='upper right')
    plt.grid()
    plt.xlabel("Round Time (ms)")
    plt.ylabel("Round Number") 

    plt.tight_layout()
    plt.savefig('charts/trace-plot.png')

