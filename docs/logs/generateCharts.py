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
four_nodes = 0
two_nodes = 0

# Data aggregation
slot_length = 1
node_number = 0

# Throughput Regex
pattern = r'\b\d+(?:\.\d+)?\s*(?:bits|Kbits|Mbits)\/sec\b'

# Shapiro-Wilk Alpha
alpha = 0.05

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
                'Instant' : instants,
                'Throughput' : values,
            }

            df = pd.DataFrame(data)
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
            data = get_data(folder + '/two-node')
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
    return


def main():

    if(slot_length):
        show_slot_length()
    elif (node_number):
        show_node_number()
    else:
        print('Set data aggregation flag!')


    return 

if __name__ == "__main__":
    main()


