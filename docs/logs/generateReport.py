from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as mticker

SLOT_LEN_MICRO = 1000000
TEST_NAME = 'ratdma-sync'
TEST_TYPE = '2nodes-1second'
NODES = ['drone1', 'drone2']
PATH = './' + TEST_NAME + '/' + TEST_TYPE + '/'
MAX_ROUNDS = 10
ROUND_OFFSET = 1
drone_data = dict()

CONSIDER_PACKETS_FLAG = False

node_colors = ['#0000ff', 
               '#ff2c2c',
               '#008000', 
               '#fd3db5', 
               '#ffde21', 
               '#00ffff']

def read_data(node_name):

    drone_data[node_name] = round_data = dict()

    with open(PATH + node_name + '.txt', "r") as file:

        round_counter = -1

        for line in file:

            stripped_line = line.strip()

            #Check if a new round has begun and increment counter
            if '[TDMA ROUND]' in stripped_line:
                round_counter+=1
                round_data[round_counter] = dict()

            if '[DELAY]' in stripped_line:
                
                current_round_data = round_data[round_counter]

                #Init DELAY entry if not yet available
                if 'DELAY' not in current_round_data.keys():
                    delay_data = current_round_data['DELAY'] = dict()
                    delay_data['received_node_id'] = list()
                    delay_data['received_slot_id'] = list()
                    delay_data['packet_arrival_time'] = list()
                    delay_data['delay'] = list()
                    delay_data['round_sent'] = list()
                
                #Valid place to store data from parsed DELAYS
                delay_data = current_round_data['DELAY']

                #Parse line
                data = stripped_line.split('[DELAY]')[1]
                split_data = data.split('|')
                
                #Save data
                delay_data['received_node_id'].append(int(split_data[0].strip()))
                delay_data['received_slot_id'].append(int(split_data[1].strip()))
                delay_data['packet_arrival_time'].append(int(split_data[2].strip()))
                delay_data['delay'].append(int(split_data[3].strip()))
                delay_data['round_sent'].append(int(split_data[4].strip()))

            if '[OFFSET]' in stripped_line:
                
                current_round_data = round_data[round_counter]

                data = stripped_line.split('[OFFSET]:')[1]
                current_round_data['OFFSET'] = int(data)

            if '[TOTAL OFFSET]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[TOTAL OFFSET]:')[1]
                current_round_data['TOTAL_OFFSET'] = int(data)

            if '[SLOT_START]' in stripped_line:

                CONSIDER_PACKETS_FLAG = True

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[SLOT_START]:')[0]
                clean_data = data.removeprefix('[ ').strip().removesuffix(']')
                split_data = clean_data.split('.')
                timestamp = int(str(split_data[0]) + str(split_data[1])) #Timestamp in microseconds
                current_round_data['SLOT_START'] = int(timestamp)

            if '[SLOT_END]' in stripped_line:
                
                CONSIDER_PACKETS_FLAG = False

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[SLOT_END]:')[0]
                clean_data = data.removeprefix('[ ').strip().removesuffix(']')
                split_data = clean_data.split('.')
                timestamp = int(str(split_data[0]) + str(split_data[1])) #Timestamp in microseconds
                current_round_data['SLOT_END'] = int(timestamp)

            if '[PARENT]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[PARENT]:')[1]
                current_round_data['PARENT'] = int(data)

            if '[SLOT_ID]' in stripped_line:
                
                if(round_counter in round_data.keys()):

                    current_round_data = round_data[round_counter]

                    data = stripped_line.split('[SLOT_ID]:')[1]
                    current_round_data['SLOT_ID'] = int(data)

            if '[RECEIVED_PACKET]' in stripped_line:

                if(CONSIDER_PACKETS_FLAG):

                    current_round_data = round_data[round_counter]

                    #Init RECEIVED_PACKET entry if not yet available
                    if 'RECEIVED_PACKET' not in current_round_data.keys():
                        packet_data = current_round_data['RECEIVED_PACKET'] = dict()
                        packet_data['received_slot_id'] = list()
                        packet_data['timestamp'] = list()
                        packet_data['relative_timestamp'] = list()
                    

                    #Valid place to store data from parsed RECEIVED_PACKETSs
                    packet_data = current_round_data['RECEIVED_PACKET']
                    
                    #Parse
                    split_line = stripped_line.split('[RECEIVED_PACKET]')
                    
                    #Timestamp
                    clean_time = split_line[0].strip().removeprefix('[').removesuffix(']')
                    split_time = clean_time.split('.')
                    timestamp = int(str(split_time[0]) + str(split_time[1])) #Timestamp in microseconds
                    
                    #Slot id, Relative Timestamp
                    data = split_line[1].split('|')
                    
                    #Save
                    packet_data['received_slot_id'].append(int(data[0].strip()))
                    packet_data['timestamp'].append(timestamp)
                    packet_data['relative_timestamp'].append(int(data[1].strip()))

def build_average_offset_chart(data):
    
    plt.clf()

    for node_name in data.keys():
        
        x = data[node_name]['average_offset_x']
        y = data[node_name]['average_offset_y']

        plt.plot(x, y, marker='o', linestyle='-', color=node_colors[int(node_name.split('drone')[1]) - 1], label = node_name)
    
    plt.xlabel("Round Number")
    plt.ylabel("Average Offset (s)")
    plt.title("Average Offset per Round")
    plt.ticklabel_format(axis='y', style='sci', scilimits=(9,9))
    plt.legend()
    plt.grid(True)

    plt.savefig("./" + TEST_NAME + "/" + TEST_TYPE + "/average-offset.png", dpi=300, bbox_inches='tight')


def build_total_offset_chart(data):
    
    plt.clf()

    for node_name in data.keys():

        x = data[node_name]['total_offset_x']
        y = data[node_name]['total_offset_y']

        plt.plot(x, y, marker='o', linestyle='-', color=node_colors[int(node_name.split('drone')[1]) - 1], label = node_name)
    
    plt.xlabel("Round Number")
    plt.ylabel("Total Offset (s)")
    plt.title("Total Offset per Round")
    plt.ticklabel_format(axis='y', style='sci', scilimits=(9,9))
    plt.legend()
    plt.grid(True)

    plt.savefig("./" + TEST_NAME + "/" + TEST_TYPE + "/total-offset.png", dpi=300, bbox_inches='tight')

def get_overlapped_packets_percentage(packet_arrival_times, slot_start):

    overlapped_packets_percentage = 0

    if(len(packet_arrival_times) > 0):
        last_packet = packet_arrival_times[-1]
        first_packet = packet_arrival_times[0]
        overlapped_delta = abs(last_packet - first_packet)
        
        overlapped_packets_percentage = (overlapped_delta / SLOT_LEN_MICRO) * 100

    return overlapped_packets_percentage
    

def build_overlap_chart(data):

    plt.clf()

    for node_name in data.keys():

        overlap_y = list()

        for i in data[node_name]['overlap_x']:

            packet_arrival_times = data[node_name]['packet_arrival_time'][i]

            slot_start = data[node_name]['slot_start'][i]

            overlapped_packets = get_overlapped_packets_percentage(packet_arrival_times, slot_start)
            overlap_y.append(overlapped_packets)
            #print(overlapped_packets, i)

        plt.plot(data[node_name]['overlap_x'], overlap_y, marker='o', linestyle='-', color=node_colors[int(node_name.split('drone')[1]) - 1], label = node_name)

    plt.xlabel("Round Number")
    plt.ylabel("Slot Overlap (%)")
    plt.title("Slot Overlap per Round")
    plt.legend()
    plt.grid(True)

    plt.savefig("./" + TEST_NAME + "/" + TEST_TYPE + "/slot-overlap.png", dpi=300, bbox_inches='tight')

def filter_packets_by_slot(packet_data_array, slot_id_array, slot_id, key, node_name):
    
    return_list = list()

    for i in range(0, len(packet_data_array)):
        
        # Check if packet received is from desired slot
        if slot_id_array[i] == slot_id:
            return_list.append(packet_data_array[i])
        #else:
            #print(slot_id_array[i], slot_id, key, node_name)

    return return_list

def build_delay_histograms(data):
    
    plt.clf()

    for node_name in data.keys():

        n_rounds = len(data[node_name]['packet_delay'])
        values = data[node_name]['packet_delay']

        fig, axes = plt.subplots(min(MAX_ROUNDS, n_rounds), 1, figsize=(8, 15))

        for i, ax in enumerate(axes):

            index = i + ROUND_OFFSET

            if index > n_rounds:
                break

            if len(values[index]) > 0:
    
                minimum = min(values[index])
                maximum = max(values[index])
        
                ax.hist(values[index], bins='auto', alpha=0.7)
                ax.set_ylabel('Round ' + str(index))
                ax.set_xlabel('Packet Delays (s)')
                ax.grid(True, linestyle="--", alpha=0.5)
                ax.axvline(x = np.average(values[index]), color = 'r',  linewidth=3, zorder=2)
                ax.axvline(x = min(values[index]), color = 'g',  linewidth=3, zorder=2)
                ax.axvline(x = max(values[index]), color = 'b',  linewidth=3, zorder=2)
                ax.ticklabel_format(axis='x', style='sci', scilimits=(9,9))

        plt.savefig("./" + TEST_NAME + "/" + TEST_TYPE + "/round-delay-hist-" + node_name + ".png", dpi=300, bbox_inches='tight')


def filter_packets_by_parent(delays_array, sender_array, parent):
    
    return_list = list()

    for i in range(0, len(delays_array)):
        # Check if packet received is from parent
        if sender_array[i] == parent:
            return_list.append(delays_array[i])

    
    return return_list


def build_charts():

    data = dict()

    for node_name in NODES:

        round_data = drone_data[node_name]
        node_data = data[node_name] = dict()

        node_data['average_offset_x'] = list()
        node_data['average_offset_y'] = list()
        node_data['total_offset_x'] = list()
        node_data['total_offset_y'] = list()
        node_data['overlap_x'] = list()
        node_data['slot_start'] = list()
        node_data['slot_end'] = list()
        node_data['packet_arrival_time'] = list()
        node_data['packet_delay'] = list()
    
        for key in round_data.keys():
            
            current_round_data = round_data[key]

            if 'OFFSET' in current_round_data.keys():
                node_data['average_offset_x'].append(key)
                node_data['average_offset_y'].append(current_round_data['OFFSET'])

            if 'TOTAL_OFFSET' in current_round_data.keys():
                node_data['total_offset_x'].append(key)
                node_data['total_offset_y'].append(current_round_data['TOTAL_OFFSET'])

            if 'SLOT_START' in current_round_data.keys():
                node_data['overlap_x'].append(key)
                node_data['slot_start'].append(current_round_data['SLOT_START'])
            
            if 'SLOT_END' in current_round_data.keys():
                node_data['slot_end'].append(current_round_data['SLOT_END'])

            if 'DELAY' in current_round_data.keys() and 'PARENT' in current_round_data.keys():
                
                delay_data = current_round_data['DELAY']
                results = filter_packets_by_parent(delay_data['delay'], delay_data['received_node_id'], current_round_data['PARENT'])
                node_data['packet_delay'].append(results)

            if ('RECEIVED_PACKET' in current_round_data.keys()) and ('SLOT_ID' in current_round_data.keys()): 

                packet_data = current_round_data['RECEIVED_PACKET']
                results = filter_packets_by_slot(packet_data['timestamp'], packet_data['received_slot_id'], current_round_data['SLOT_ID'] - 1, key, node_name)
                node_data['packet_arrival_time'].append(results)
            
            else:
                node_data['packet_arrival_time'].append([])

    build_average_offset_chart(data)
    build_total_offset_chart(data)
    build_overlap_chart(data)
    build_delay_histograms(data)

        


if __name__ == '__main__':

    for node_name in NODES:
        read_data(node_name)

    build_charts()

    