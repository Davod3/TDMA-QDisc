import os
import re
import pandas as pd
import numpy as np
from scipy.stats import shapiro
from numpy.random import randn
import matplotlib.pyplot as plt

#Flags
# Protocol Type
udp = 1
tcp = 0
filetransfer = 0

test_folders = ['./noqdisc-tests', 
               './tdma-50ms-slot-tests', 
               './tdma-100ms-slot-tests',
               './tdma-250ms-slot-tests',
               './tdma-500ms-slot-tests',
               './tdma-baseline-tests']

# Number of Nodes
six_nodes = 1
four_nodes = 1
two_nodes = 1

# Data aggregation
slot_length = 0
node_number = 1
over_time = 0

# Throughput Regex
pattern = r'\b\d+(?:\.\d+)?\s*(?:bits|Kbits|Mbits)\/sec\b'

# Shapiro-Wilk Alpha
alpha = 0.05

# Node Colors
node_colors = ['#e31919', '#1919e3', '#0fad0c', '#7a0cad', '#542d03', '#d1af06']

def convert_to_mbits(data):

    if 'Kbits' in data[1]:
        #Convert from Kbits/sec to Mbits/sec
        return [float(data[0]) / 1000, 'Mbits/sec']
    else:
        #Convert from Bits/sec to Mbits/sec
        return [float(data[0]) / 1_000_000, 'Mbits/sec']

def parse_udp_logs(folder):

    file_list = os.listdir(folder)
    dataframes = []

    file_list.sort()

    for file in file_list:
        if 'drone' in file:            
            f = open(folder + '/' + file, "r")
            n_lines = 0
            instants = []
            values = []
            for l in f:
                if 'sec' in l and '%' not in l:
                    matches = re.findall(pattern, l)
                    split_match = matches[0].split(' ')

                    if 'Mbits' in split_match[1]:
                        #Good. Save data
                        instants.append(n_lines)
                        values.append(split_match[0])
                    else:
                        #Convert to Mbits/sec
                        converted_data = convert_to_mbits(split_match)
                        instants.append(n_lines)
                        values.append(converted_data[0])

                    n_lines+=1

            data = {
                'Instant' : instants[5:-5],
                'Throughput' : values[5:-5],
            }

            df = pd.DataFrame(data)
            df['Throughput'] = df['Throughput'].astype(float)
            dataframes.append({'node' : file.split('.txt')[0],
                               'data' : df})
            

    return dataframes

def parse_tcp_logs(folder):
    return

def parse_filetransfer_logs(folder):
    return

def get_data(folder):

    data = []

    if(udp):
        data = parse_udp_logs(folder + 'throughput-udp')
    elif(tcp):
        data = parse_tcp_logs(folder + 'throughput')
    elif(filetransfer):
        data = parse_filetransfer_logs(folder + 'filetransfer')
    else:
        print('Set protocol type flag') 

    return data

def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    #plt.setp(bp['caps'], color=color)
    #plt.setp(bp['medians'], color=color)
    
    for box in bp['boxes']:
        box.set_facecolor(color)

def test_normality(aggregated_data):

        for key in aggregated_data.keys():
        
            data = aggregated_data[key]

            print('------------------------' + key + '-------------------------------------')
            
            for data_object in data:

                node_name = data_object['node']
                data = data_object['data']

                stat, p_value = shapiro(data['Throughput'])

                #histogram_data = [data['Instant'], data['Throughput']]

                print(node_name + ' - Is distribution normal? ' + ('Yes' if p_value > alpha else 'No'))

                #plt.hist(histogram_data, edgecolor='black', bins=20)

def show_slot_length():

    aggregated_data = dict()

    for folder in test_folders:
        
        if(six_nodes):
            data = get_data(folder + '/six-node-')
        elif(four_nodes):
            data = get_data(folder + '/four-node-')
        elif(two_nodes):
            data = get_data(folder + '/two-node-')
        else:
            print('Set number of nodes flag!')

        if 'noqdisc' in folder:
            aggregated_data['noqdisc'] = data
        else:
            split_folder = folder.split('-')
            aggregated_data[split_folder[1]] = data

    #Create charts and run statistical tests
    
    #Normality test
    test_normality(aggregated_data)

    #Plot



def show_node_number():

    fig, ax = plt.subplots(figsize=(20, 15))

    aggregated_data = dict()
    ticks = []
    boxplot_data = dict()

    #Set to whichever folder you want
    folder = test_folders[1]

    if(two_nodes):
        data = get_data(folder + '/two-node-')
        aggregated_data['two-nodes'] = data
    if(four_nodes):
        data = get_data(folder + '/four-node-')
        aggregated_data['four-nodes'] = data
    if(six_nodes):
        data = get_data(folder + '/six-node-')
        aggregated_data['six-nodes'] = data

    for key in aggregated_data:
        
        data_object_list = aggregated_data[key]
        ticks.append(key)

        for data_object in data_object_list:

            df = data_object['data']
            
            if(data_object['node'] in boxplot_data.keys()):
                boxplot_data[data_object['node']].append(df['Throughput'])
            else:
                boxplot_data[data_object['node']] = []
                boxplot_data[data_object['node']].append(df['Throughput'])

    plt.figure()

    index = 0

    for key in boxplot_data.keys():
        data_array = boxplot_data[key]
        positions = []
        offset = 3 - len(data_array)

        if(index % 2 == 0):
            positions=np.array(range(offset,len(data_array)+offset))*6.0-(0.6*index) 
        else:
            positions=np.array(range(offset,len(data_array)+offset))*6.0+(0.6*index)

        bp = plt.boxplot(data_array, positions=positions, sym='', widths=0.6, patch_artist=True)
        set_box_color(bp, node_colors[index])

        #Temporary line just for the legend
        plt.plot([], c=node_colors[index], label=key)

        index+=1
    
    plt.legend()
    plt.grid()

    plt.xticks(range(0, len(ticks) * 6, 6), ticks)
    plt.xlim(-3, len(ticks)*6)

    plt.suptitle("Node Throughput VS Number of Nodes")
    plt.title('TDMA - 50ms slots')
    plt.xlabel("Number of Nodes (N)")
    plt.ylabel("Throughput (Mbits/s)") 

    plt.savefig('charts/boxplot-node-number.png')
    


def show_over_time():

    aggregated_data = dict()

    #Set to whichever folder you want
    folder = test_folders[0]

    if(six_nodes):
        data = get_data(folder + '/six-node-')
    elif(four_nodes):
        data = get_data(folder + '/four-node-')
    elif(two_nodes):
        data = get_data(folder + '/two-node-')
    else:
        print('Set number of nodes flag!')

    if 'noqdisc' in folder:
        aggregated_data['noqdisc'] = data
    else:
        split_folder = folder.split('-')
        aggregated_data[split_folder[1]] = data

    #Normality test
    test_normality(aggregated_data)

    fig, ax = plt.subplots(figsize=(20, 15))

    for key in aggregated_data:
        entry_list = aggregated_data[key]
        current_min_x = 0
        current_max_x = 0
        current_min_y = 0
        current_max_y = 0
        
        for entry in entry_list:
            
            data = entry['data']
            node_name = entry['node']

            #data['Throughput'] = data['Throughput'].astype(float)

            x = np.array(data['Instant'])
            y = np.array(data['Throughput'])

            if min(x) < current_min_x:
                current_min_x = min(x)
            if max(x) > current_max_x:
                current_max_x = max(x)
            if min(y) < current_min_y:
                current_min_y = min(y)
            if max(y) > current_max_y:
                current_max_y = max(y)

            ax.plot(x,y, label=node_name)

        ax.set_title('Node throughput over time')
        ax.set_xlabel('Instant (seconds)')
        ax.set_ylabel('Throughput (Mbits/s)')
        ax.set_xticks(range(int(current_min_x), int(current_max_x) + 1))
        ax.set_yticks(range(int(current_min_y), int(current_max_y) + 1))
        ax.legend()

        plt.savefig('charts/line-' + key + '.png', bbox_inches='tight')

def main():

    if(slot_length):
        show_slot_length()
    elif (node_number):
        show_node_number()
    elif(over_time):
        show_over_time()
    else:
        print('Set data aggregation flag!')


    return 

if __name__ == "__main__":
    main()


