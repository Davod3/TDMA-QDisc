from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as mticker

def process_delays(path):
    
    values = dict()


    with open(path, "r") as file:

        round_counter = -1

        for line in file:

            stripped_line = line.strip()

            if '[TDMA ROUND]' in stripped_line:
                round_counter+=1
                values[round_counter] = []

            elif '[DELAY]' in stripped_line:
                split_line = stripped_line.split(' ')
                delay = int(split_line[3])
            
                values[round_counter].append(delay)


    fig, axes = plt.subplots(round_counter, 1, figsize=(8, 15))

    for i, ax in enumerate(axes):
        
        if len(values[i]) > 0:
    
            print(i)
    
            minimum = min(values[i])
            maximum = max(values[i])
    
            print(minimum, maximum)
    
            ax.hist(values[i], bins='auto', alpha=0.7)
            ax.set_ylabel('Round ' + str(i))
            ax.set_xlabel('Packet Delays (s)')
            ax.grid(True, linestyle="--", alpha=0.5)
            ax.axvline(x = np.median(values[i]), color = 'r',  linewidth=3, zorder=2)
            ax.axvline(x = min(values[i]), color = 'g',  linewidth=3, zorder=2)
            ax.axvline(x = max(values[i]), color = 'b',  linewidth=3, zorder=2)
            ax.ticklabel_format(axis='x', style='sci', scilimits=(9,9))

    plt.tight_layout()
    plt.savefig('charts/packet-delays.png')

if __name__ == '__main__':

    process_delays('./delay-tests/2-nodes/drone1.txt')

    