from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as mticker

MAX_ROUNDS = 10
ROUND_OFFSET = 50

def process_delays(path):
    
    values = dict()


    with open(path, "r") as file:

        round_counter = -1
        valid_round_counter = 0

        for line in file:

            stripped_line = line.strip()

            if '[TDMA ROUND]' in stripped_line:
                round_counter+=1

                if(round_counter >= ROUND_OFFSET):
                    values[round_counter] = []
                    valid_round_counter+=1

                    if valid_round_counter > MAX_ROUNDS:
                        break

            elif '[DELAY]' in stripped_line:

                if(round_counter >= ROUND_OFFSET):
                    split_line = stripped_line.split('[DELAY]')

                    delay = int(split_line[1])

                    values[round_counter].append(delay)


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
            ax.axvline(x = np.median(values[index]), color = 'r',  linewidth=3, zorder=2)
            ax.axvline(x = min(values[index]), color = 'g',  linewidth=3, zorder=2)
            ax.axvline(x = max(values[index]), color = 'b',  linewidth=3, zorder=2)
            ax.ticklabel_format(axis='x', style='sci', scilimits=(9,9))



    plt.tight_layout()
    plt.savefig('charts/packet-delays.png')

if __name__ == '__main__':

    process_delays('./delay-tests/2-nodes-50ms/drone2.txt')

    