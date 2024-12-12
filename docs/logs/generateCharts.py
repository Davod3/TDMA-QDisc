import os
import re
import pandas as pd
import numpy as np
from scipy.stats import shapiro
from numpy.random import randn
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, FuncFormatter
import scipy.optimize as opt;

#Flags
# Protocol Type
udp = 0
tcp = 0
filetransfer = 0
sync_progression = 1

test_folders = ['./noqdisc-tests', 
               './tdma-50ms-slot-tests',]

# Number of Nodes
six_nodes = 1
four_nodes = 0
two_nodes = 0

# Data aggregation
distributions = 0
node_number = 0
over_time = 1

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
        if 'drone' in file and 'ntp' not in file:            
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
    elif(sync_progression):
        data = parse_udp_logs(folder + 'sync-progression')
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

def show_distributions():

    aggregated_data = dict()

    for folder in test_folders:
        
        fig, axes = plt.subplots(12, 1, figsize=(8, 30))
        index = 0

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
            
            for data_object in data_object_list:
                
                df = data_object['data']
                axes[index].hist(df['Throughput'], bins=30, color='blue', alpha=0.7)   
                axes[index].set_title(key + '-' + data_object['node'])
                axes[index].set_xlabel('Throughput (Mbits/s)')
                axes[index].set_ylabel('Ocurrences')
                axes[index].hist(df['Throughput'])

                index+=1

        plt.tight_layout()
        plt.savefig('charts/distributions/' + folder + '.png')


def custom_tick_formatter_line_y(value, _):
    # Only label certain ticks (e.g., 10, 15, etc.)
    if value in [10, 15, 20, 25, 30, 35]:
        return f"{value}"
    return ""  # Hide other ticks

def custom_tick_formatter_line_x(value, _):
    # Only label certain ticks (e.g., 10, 15, etc.)
    if value in [2,4,6]:
        return f"{value}"
    return ""  # Hide other ticks

def show_node_number_line():

    fig, ax = plt.subplots(figsize=(20, 15))
    aggregated_data_tdma = dict()
    aggregated_data_csma = dict()

    tdma_y = []
    tdma_error = []
    csma_y = []
    csma_error = []
    x = []

    #Set to whichever folder you want
    folder_tdma = test_folders[1]
    folder_csma = test_folders[0]

    if(two_nodes):
        
        data = get_data(folder_tdma + '/two-node-')
        aggregated_data_tdma['two-nodes'] = data

        data = get_data(folder_csma + '/two-node-')
        aggregated_data_csma['two-nodes'] = data

        x.append(2)

    if(four_nodes):
        data = get_data(folder_tdma + '/four-node-')
        aggregated_data_tdma['four-nodes'] = data

        data = get_data(folder_csma + '/four-node-')
        aggregated_data_csma['four-nodes'] = data

        x.append(4)

    if(six_nodes):
        data = get_data(folder_tdma + '/six-node-')
        aggregated_data_tdma['six-nodes'] = data

        data = get_data(folder_csma + '/six-node-')
        aggregated_data_csma['six-nodes'] = data

        x.append(6)
    
    for key in aggregated_data_tdma:
        data_object_list = aggregated_data_tdma[key]
        node_avg_list = []

        for data_object in data_object_list:
            
            df = data_object['data']
            avg = df['Throughput'].mean()

            node_avg_list.append(avg)
        
        tdma_y.append(np.mean(node_avg_list))
        tdma_error.append(np.std(node_avg_list))

    for key in aggregated_data_csma:
        data_object_list = aggregated_data_csma[key]
        node_avg_list = []

        for data_object in data_object_list:
            
            df = data_object['data']
            avg = df['Throughput'].mean()

            node_avg_list.append(avg)
        
        csma_y.append(np.mean(node_avg_list))
        csma_error.append(np.std(node_avg_list))
    
    ideal_y = [60/x for x in range(2,7,2)]

    plt.figure()

    plt.scatter(x, tdma_y, label='TDMA 50ms slots', marker='o', zorder=1)
    plt.plot(x, tdma_y, zorder=2)
    plt.scatter(x, csma_y, label='CSMA',marker='s', zorder=1)
    plt.plot(x, csma_y, zorder=2)
    plt.scatter(x, ideal_y, label='Ideal', marker='v', zorder=1)
    plt.plot(x, ideal_y, zorder=2)

    ax = plt.gca()
    ax.yaxis.set_major_locator(MultipleLocator(0.5))
    ax.yaxis.set_major_formatter(FuncFormatter(custom_tick_formatter_line_y))
    ax.xaxis.set_major_formatter(FuncFormatter(custom_tick_formatter_line_x))

    plt.legend()
    plt.title("Node Throughput VS Number of Nodes")
    plt.xlabel("Number of Nodes (N)")
    plt.ylabel("Average Throughput (Mbits/s)") 

    plt.savefig('charts/errorbar-node-number.png')

def show_sync():

    aggregated_data = dict()

    #Set to whichever folder you want
    folder = test_folders[1]

    if(six_nodes):
        data = get_data(folder + '/six-node-')
        aggregated_data['six-nodes'] = data
    else:
        print('Set number of nodes flag!')

    fig, ax = plt.subplots(figsize=(15, 6))

    for key in aggregated_data:
        
        data_object_list = aggregated_data[key]

        for data_object in data_object_list:

            df = data_object['data']
            
            plt.bar(df['Instant'],df['Throughput'], label=data_object['node'])
    
    plt.legend()

    ax = plt.gca()
    ax.xaxis.set_major_locator(MultipleLocator(50))

    plt.suptitle("Node Throughput VS Time")
    plt.xlabel("Time (Seconds)")
    plt.ylabel("Throughput (Mbits/s)") 

    plt.savefig('charts/line-sync-progression.png')

def show_node_number_boxplot():

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

    if(distributions):
        show_distributions()
    elif (node_number):
        #show_node_number_boxplot()
        show_node_number_line()
    elif(over_time):
        #show_over_time()
        show_sync()
    else:
        print('Set data aggregation flag!')


    return 

if __name__ == "__main__":
    main()


