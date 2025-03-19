from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as mticker

TEST_NAME = 'ratdma-sync'
TEST_TYPE = '2nodes-1second'
NODE_NAME = 'drone2'
PATH = './' + TEST_NAME + '/' + TEST_TYPE + '/' + NODE_NAME + '.txt'
MAX_ROUNDS = 10
ROUND_OFFSET = 0
round_data = dict()

def read_data(path):

    with open(path, "r") as file:

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

            if '[OFFSET]' in stripped_line:
                
                current_round_data = round_data[round_counter]

                data = stripped_line.split('[OFFSET]:')[1]
                current_round_data['OFFSET'] = int(data)

            if '[TOTAL OFFSET]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[TOTAL OFFSET]:')[1]
                current_round_data['TOTAL_OFFSET'] = int(data)

            if '[SLOT_START]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[SLOT_START]:')[1]
                current_round_data['SLOT_START'] = int(data)

            if '[SLOT_END]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[SLOT_END]:')[1]
                current_round_data['SLOT_END'] = int(data)

            if '[PARENT]' in stripped_line:

                current_round_data = round_data[round_counter]

                data = stripped_line.split('[PARENT]:')[1]
                current_round_data['SLOT_START'] = int(data)

            


    

    '''
    fig, axes = plt.subplots(min(MAX_ROUNDS, round_counter), 1, figsize=(8, 15))

    for i, ax in enumerate(axes):

        index = i + ROUND_OFFSET

        if index > round_counter:
            break

        if len(values[index]) > 0:
    
            minimum = min(values[index])
            maximum = max(values[index])
    
            print(minimum, maximum)
    
            ax.hist(values[index], bins='auto', alpha=0.7)
            ax.set_ylabel('Round ' + str(index))
            ax.set_xlabel('Packet Delays (s)')
            ax.grid(True, linestyle="--", alpha=0.5)
            ax.axvline(x = np.average(values[index]), color = 'r',  linewidth=3, zorder=2)
            ax.axvline(x = min(values[index]), color = 'g',  linewidth=3, zorder=2)
            ax.axvline(x = max(values[index]), color = 'b',  linewidth=3, zorder=2)
            ax.ticklabel_format(axis='x', style='sci', scilimits=(9,9))



    plt.tight_layout()
    plt.savefig('charts/packet-delays.png')'
    '''

if __name__ == '__main__':

    read_data(PATH)


    