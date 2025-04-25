from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt
import os

TEST_NAME = "tree-topology"
TEST_TYPE = "tdma"
TRACE_NAME = "trace-6nodes.pcapng.gz"

DRONE_1_ID = 0
DRONE_2_ID = 1
DRONE_3_ID = 2
DRONE_4_ID = 3
DRONE_5_ID = 4
DRONE_6_ID = 5

node_wlan_sa = ['d8:3a:dd:34:b7:cd', 
                'd8:3a:dd:34:b8:d5', 
                'd8:3a:dd:e0:9c:d4', 
                'd8:3a:dd:e0:9f:f3', 
                'd8:3a:dd:96:7a:78', 
                'd8:3a:dd:96:6e:12']

node_colors = ['#0000ff', 
               '#ff2c2c',
               '#008000', 
               '#d211bd', 
               '#ffde21', 
               '#ff7800']

tdma_round_len_ms = 300
offset = 35

#GLOBAL VARS
first_packets_timestamp_ms = dict()
last_rounds = dict()
first_packet_flags = dict()
round_counter = 0
saved_positions = dict()
node1_first_packet_ms = None
throughput_round_data = dict()
throughput_round_counter = 0

#Throughput Regex
pattern = r'\b(\d+(?:\.\d+)?)\s*(\w+Bytes)\b'

def convert_to_bytes(data, unit):

    if unit == 'KBytes':
        #Convert from KBytes to Bytes
        return float(data) * 1000
    elif unit == 'MBytes':
        #Convert from MBytes to Bytes
        return float(data) * 1_000_000
    else:
        return float(data)

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

            if relative_timestamp_ms > 70000:

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

    plt.legend(loc='upper right')
    plt.grid()
    plt.xlabel("Round Time (ms)")
    plt.ylabel("Round Number") 

    plt.tight_layout()
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'trace-plot.png')

def position_process_packet(packet_timestamp_ms, packet_round, reference_node, me):
    
    global first_packets_timestamp_ms
    global last_rounds
    global first_packet_flags
    global round_counter
    global saved_positions

    position = 0

    if(reference_node in first_packet_flags.keys() and first_packet_flags[reference_node]):

        #First packet of Reference Node is available. Check my last first packet and calculate position
        if(me in first_packet_flags.keys() and first_packet_flags[me]):
            
            if(me != reference_node):
                first_packet_flags[me] = False
                position = first_packets_timestamp_ms[me] - first_packets_timestamp_ms[reference_node]
            else:
                position = 0

            if(round_counter in saved_positions.keys()):

                saved_positions[round_counter][me] = position
                
            else:

                saved_positions[round_counter] = dict()
                saved_positions[round_counter][me] = position

                    

            

    if(me in first_packets_timestamp_ms.keys() and me in last_rounds.keys() and me in first_packet_flags.keys()):
        
        last_round = last_rounds[me]

        if(packet_round != last_round):
            #Round has changed. Current packet should be new first
            first_packets_timestamp_ms[me] = packet_timestamp_ms
            last_rounds[me] = packet_round
            first_packet_flags[me] = True

            #If round changes and i'm reference node, update round counter
            if me == reference_node:
                round_counter+=1

    else:
        last_rounds[me] = packet_round
        first_packets_timestamp_ms[me] = packet_timestamp_ms
        first_packet_flags[me] = True

    return


def compute_position(path):

    first_packet_time_ms = 0
    packet_counter = 0

    global saved_positions

    for packet in PcapReader(path):

        #if(packet_counter > 2000):
        #    break

        dot11 = packet['Dot11']

        if dot11.type != 2:
            continue

        timestamp_ms = packet.time * 1000

        if not first_packet_time_ms:
            first_packet_time_ms = timestamp_ms

        relative_timestamp_ms = timestamp_ms - first_packet_time_ms
        
        if IP in packet:
            ip_layer = packet[IP]
            ip_header_raw = bytes(ip_layer)[:ip_layer.ihl * 4]
            
            #Check if packet is annotaded
            if(ip_layer.ihl == 14):

                print(packet_counter)
                packet_counter+=1

                wlan_source_address = dot11.addr2

                options = ip_header_raw[20:]
                annotations = options[-10:-2]

                packet_round = int.from_bytes(annotations, byteorder='little')

                if wlan_source_address == node_wlan_sa[DRONE_1_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_1_ID)
                if wlan_source_address == node_wlan_sa[DRONE_2_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_2_ID)
                if wlan_source_address == node_wlan_sa[DRONE_3_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_3_ID)
                if wlan_source_address == node_wlan_sa[DRONE_4_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_4_ID)
                if wlan_source_address == node_wlan_sa[DRONE_5_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_5_ID)
                if wlan_source_address == node_wlan_sa[DRONE_6_ID]:
                    position_process_packet(relative_timestamp_ms, packet_round, DRONE_1_ID, DRONE_6_ID)


    position_data = dict()

    #For each round recorded
    for key in saved_positions.keys():

        round_data = saved_positions[key]

        #Grab data for each node
        for i in range(0, len(node_colors)):
            
            #If node data not yet initialized, init
            if i not in position_data.keys():
                position_data[i] = list()

            #If node has data for this round, save it
            if(i in round_data.keys()):
                position = round_data[i]
                position_data[i].append(position)
            else:
                #Else, just consider the position 0
                position_data[i].append(0)

    overlap_x = range(0, len(list(saved_positions.keys())))[:-1]

    #position_data should now be a dict with a key for each node and a value corresponding to a list of positions over rounds. Plot it
    plt.figure(figsize=(15,10))
    plt.clf()
    plt.plot(overlap_x, position_data[DRONE_1_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_1_ID], label = "Drone 1")
    plt.axhline(y=0, color=node_colors[DRONE_1_ID], linestyle='-', linewidth=2)

    plt.plot(overlap_x, position_data[DRONE_2_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_2_ID], label = "Drone 2")
    plt.axhline(y=50, color=node_colors[DRONE_2_ID], linestyle='-', linewidth=2)

    plt.plot(overlap_x, position_data[DRONE_3_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_3_ID], label = "Drone 3")
    plt.axhline(y=100, color=node_colors[DRONE_3_ID], linestyle='-', linewidth=2)

    plt.plot(overlap_x, position_data[DRONE_4_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_4_ID], label = "Drone 4")
    plt.axhline(y=150, color=node_colors[DRONE_4_ID], linestyle='-', linewidth=2)

    plt.plot(overlap_x, position_data[DRONE_5_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_5_ID], label = "Drone 5")
    plt.axhline(y=200, color=node_colors[DRONE_5_ID], linestyle='-', linewidth=2)

    plt.plot(overlap_x, position_data[DRONE_6_ID][:-1], marker='o', linestyle='dotted', color=node_colors[DRONE_6_ID], label = "Drone 6")
    plt.axhline(y=250, color=node_colors[DRONE_6_ID], linestyle='-', linewidth=2)

    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Relative Slot Position (ms) ")
    plt.title("Slot start positions relative to Drone 1")
    plt.tight_layout()
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-position.png')

def tdma_count_packet(me, relative_timestamp_ms, packet):

    global node1_first_packet_ms
    global throughput_round_data
    global throughput_round_counter

    #Sets the first time a packet from Node 1 was received 
    if node1_first_packet_ms == None and me == DRONE_1_ID:
        node1_first_packet_ms = relative_timestamp_ms

    if(node1_first_packet_ms == None and me != DRONE_1_ID):
        return

    #If packet is received within tdma_round_len of Node 1, then count it
    if relative_timestamp_ms - node1_first_packet_ms <= tdma_round_len_ms:

        #If round has value, increment, else, init
        if throughput_round_counter in throughput_round_data.keys():
            throughput_round_data[throughput_round_counter]+=len(packet)
        else:
            throughput_round_data[throughput_round_counter]=len(packet)
    
    else:

        #If packet is received outside tdma_round_len of Node 1, check if packet is from Node1. If so, increase round and reset time
        if me == DRONE_1_ID:
            node1_first_packet_ms = relative_timestamp_ms
            throughput_round_counter+=1


def tdma_network_throughput(tdma_path):
    
    first_packet_time_ms = 0

    global throughput_round_data
    throughput_packet_counter = 0

    for packet in PcapReader(tdma_path):

        dot11 = packet['Dot11']

        if dot11.type != 2:
            continue

        timestamp_ms = packet.time * 1000

        if not first_packet_time_ms:
            first_packet_time_ms = timestamp_ms

        relative_timestamp_ms = timestamp_ms - first_packet_time_ms
        wlan_source_address = dot11.addr2

        print(throughput_packet_counter)
        throughput_packet_counter+=1

        if wlan_source_address == node_wlan_sa[DRONE_1_ID]:
            tdma_count_packet(DRONE_1_ID, relative_timestamp_ms, packet)
        if wlan_source_address == node_wlan_sa[DRONE_2_ID]:
            tdma_count_packet(DRONE_2_ID, relative_timestamp_ms, packet)
        if wlan_source_address == node_wlan_sa[DRONE_3_ID]:
            tdma_count_packet(DRONE_3_ID, relative_timestamp_ms, packet)
        if wlan_source_address == node_wlan_sa[DRONE_4_ID]:
            tdma_count_packet(DRONE_4_ID, relative_timestamp_ms, packet)
        if wlan_source_address == node_wlan_sa[DRONE_5_ID]:
            tdma_count_packet(DRONE_5_ID, relative_timestamp_ms, packet)
        if wlan_source_address == node_wlan_sa[DRONE_6_ID]:
            tdma_count_packet(DRONE_6_ID, relative_timestamp_ms, packet)

    tdma_x = list()
    tdma_y = list()

    for key in throughput_round_data.keys():

        time_sample_ms = key * tdma_round_len_ms
        tdma_x.append(time_sample_ms)
        tdma_y.append(throughput_round_data[key])

    return (tdma_x, tdma_y)


def csma_network_throughput(csma_path):
    
    file_list = os.listdir(csma_path)
    file_list.sort()
    values = list()
    
    node_data = dict()
    files = list()

    for file in file_list:
         
        #Ignore throughput from drone1
        if 'throughput' in file:
            f = open(csma_path + '/' + file, "r")
            values = list()

            first_line = f.readline()    

            if 'None' not in first_line:
                
                files.append(file)

                for l in f:

                    if 'sec' in l and '%' not in l:

                        matches = re.findall(pattern, l)
                        
                        converted_value = 0

                        if len(matches) != 0:
                            (value, unit) = matches[0] #(data, unit) tuple
                            converted_value = convert_to_bytes(value, unit)
                            
                        values.append(converted_value)

                node_data[file] = values
            
    csma_x = list()
    csma_y = list()

    for i in range(0, len(node_data[files[0]])):

        total = 0

        for file in files:
            total+=node_data[file][i]

        csma_y.append(total)
        csma_x.append(i*1000)

    return (csma_x,csma_y)         
    
    


def compare_throughput(tdma_path, csma_path):
    
    #These functions should simply return a tuple with x and y data for the plots
    (tdma_x, tdma_y) = tdma_network_throughput(tdma_path)
    (csma_x, csma_y) = csma_network_throughput(csma_path)

    plt.figure(figsize=(15,10))
    plt.clf()
    plt.plot(tdma_x, tdma_y, marker='o', linestyle='-', color="red", label = "TDMA Throughput")
    plt.plot(csma_x[5:-5], csma_y[5:-5], marker='o', linestyle='-', color="blue", label = "CSMA Throughput")

    plt.legend()
    plt.grid()
    plt.xlabel("Sample Time (ms)")
    plt.ylabel("Network Throughput (Bytes / Sample Time)")
    plt.title("Total Network Throughput - TDMA vs CSMA")
    plt.tight_layout()
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'network-throughput.png')
        

if __name__ == '__main__':

    #process_pcap('./' + TEST_NAME +'/' + TEST_TYPE + '/' + TRACE_NAME)

    compute_position('./' + TEST_NAME +'/' + TEST_TYPE + '/' + TRACE_NAME)

    compare_throughput('./' + TEST_NAME +'/' + TEST_TYPE + '/' + TRACE_NAME, './' + TEST_NAME +'/csma')

