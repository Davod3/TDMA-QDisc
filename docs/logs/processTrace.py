from scapy.all import PcapReader
from scapy.layers.dot11 import *
import math
import matplotlib.pyplot as plt

TEST_NAME = "star-topology"
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

    plt.legend(loc='upper right')
    plt.grid()
    plt.xlabel("Round Time (ms)")
    plt.ylabel("Round Number") 

    plt.tight_layout()
    plt.savefig('charts/trace-plot.png')



def compute_overlap(path):

    first_packet_time_ms = 0

    last_rounds = dict()
    last_packet_timestamps = dict()
    first_packet_timestamps = dict()

    saved_first = dict()
    saved_last = dict()
    check_overlap_flag = dict()

    check_overlap_flag[DRONE_1_ID] = False
    check_overlap_flag[DRONE_2_ID] = False
    check_overlap_flag[DRONE_3_ID] = False
    check_overlap_flag[DRONE_4_ID] = False
    check_overlap_flag[DRONE_5_ID] = False
    check_overlap_flag[DRONE_6_ID] = False

    round_counter = 0

    packet_counter = 0

    saved_overlap = dict()

    for packet in PcapReader(path):

        #if(packet_counter > 5000):
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
                    
                    if(DRONE_1_ID in last_rounds.keys() and DRONE_1_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_1_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_1_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_1_ID] = first_packet_timestamps[DRONE_1_ID]
                            saved_last[DRONE_1_ID] = last_packet_timestamps[DRONE_1_ID]
                            check_overlap_flag[DRONE_1_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_1_ID] = relative_timestamp_ms

                            #Increase round number. Only do this for Drone 1 as it is considered the anchor.
                            round_counter+=1

                            if(round_counter not in saved_overlap.keys()):
                                saved_overlap[round_counter] = dict()

                        else:
                            last_packet_timestamps[DRONE_1_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_1_ID] = packet_round
                        last_packet_timestamps[DRONE_1_ID] = relative_timestamp_ms
                        saved_first[DRONE_1_ID] = first_packet_timestamps[DRONE_1_ID] = relative_timestamp_ms


                    #Quantify overlap with 6
                    if(check_overlap_flag[DRONE_6_ID]):
                        overlap = saved_first[DRONE_1_ID] - saved_last[DRONE_6_ID]
                        saved_overlap[round_counter][DRONE_1_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_6_ID] = False

                if wlan_source_address == node_wlan_sa[DRONE_2_ID]:

                    if(DRONE_2_ID in last_rounds.keys() and DRONE_2_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_2_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_2_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_2_ID] = first_packet_timestamps[DRONE_2_ID]
                            saved_last[DRONE_2_ID] = last_packet_timestamps[DRONE_2_ID]
                            check_overlap_flag[DRONE_2_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_2_ID] = relative_timestamp_ms
                        else:
                            last_packet_timestamps[DRONE_2_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_2_ID] = packet_round
                        last_packet_timestamps[DRONE_2_ID] = relative_timestamp_ms
                        saved_first[DRONE_2_ID] = first_packet_timestamps[DRONE_2_ID] = relative_timestamp_ms

                    #Quantify overlap with drone 1
                    if(check_overlap_flag[DRONE_1_ID]):
                        overlap = saved_first[DRONE_2_ID] - saved_last[DRONE_1_ID]

                        saved_overlap[round_counter][DRONE_2_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_1_ID] = False

                if wlan_source_address == node_wlan_sa[DRONE_3_ID]:

                    if(DRONE_3_ID in last_rounds.keys() and DRONE_3_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_3_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_3_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_3_ID] = first_packet_timestamps[DRONE_3_ID]
                            saved_last[DRONE_3_ID] = last_packet_timestamps[DRONE_3_ID]
                            check_overlap_flag[DRONE_3_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_3_ID] = relative_timestamp_ms
                        else:
                            last_packet_timestamps[DRONE_3_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_3_ID] = packet_round
                        last_packet_timestamps[DRONE_3_ID] = relative_timestamp_ms
                        saved_first[DRONE_3_ID] = first_packet_timestamps[DRONE_3_ID] = relative_timestamp_ms

                    #Quantify overlap with drone 2
                    if(check_overlap_flag[DRONE_2_ID]):
                        overlap = saved_first[DRONE_3_ID] - saved_last[DRONE_2_ID]
                        saved_overlap[round_counter][DRONE_3_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_2_ID] = False
                
                if wlan_source_address == node_wlan_sa[DRONE_4_ID]:

                    if(DRONE_4_ID in last_rounds.keys() and DRONE_4_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_4_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_4_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_4_ID] = first_packet_timestamps[DRONE_4_ID]
                            saved_last[DRONE_4_ID] = last_packet_timestamps[DRONE_4_ID]
                            check_overlap_flag[DRONE_4_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_4_ID] = relative_timestamp_ms
                        else:
                            last_packet_timestamps[DRONE_4_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_4_ID] = packet_round
                        last_packet_timestamps[DRONE_4_ID] = relative_timestamp_ms
                        saved_first[DRONE_4_ID] = first_packet_timestamps[DRONE_4_ID] = relative_timestamp_ms

                    #Quantify overlap with drone 1
                    if(check_overlap_flag[DRONE_3_ID]):
                        overlap = saved_first[DRONE_4_ID] - saved_last[DRONE_3_ID]
                        saved_overlap[round_counter][DRONE_4_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_3_ID] = False

                if wlan_source_address == node_wlan_sa[DRONE_5_ID]:

                    if(DRONE_5_ID in last_rounds.keys() and DRONE_5_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_5_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_5_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_5_ID] = first_packet_timestamps[DRONE_5_ID]
                            saved_last[DRONE_5_ID] = last_packet_timestamps[DRONE_5_ID]
                            check_overlap_flag[DRONE_5_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_5_ID] = relative_timestamp_ms
                        else:
                            last_packet_timestamps[DRONE_5_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_5_ID] = packet_round
                        last_packet_timestamps[DRONE_5_ID] = relative_timestamp_ms
                        saved_first[DRONE_5_ID] = first_packet_timestamps[DRONE_5_ID] = relative_timestamp_ms

                    #Quantify overlap with drone 4
                    if(check_overlap_flag[DRONE_4_ID]):
                        overlap = saved_first[DRONE_5_ID] - saved_last[DRONE_4_ID]
                        saved_overlap[round_counter][DRONE_5_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_4_ID] = False

                if wlan_source_address == node_wlan_sa[DRONE_6_ID]:

                    if(DRONE_6_ID in last_rounds.keys() and DRONE_6_ID in last_packet_timestamps.keys()):
                    
                        last_round = last_rounds[DRONE_6_ID]

                        #This happens, round has changed. Save first packet
                        if(packet_round > last_round):
                            last_rounds[DRONE_6_ID] = packet_round

                            #Save previous info
                            saved_first[DRONE_6_ID] = first_packet_timestamps[DRONE_6_ID]
                            saved_last[DRONE_6_ID] = last_packet_timestamps[DRONE_6_ID]
                            check_overlap_flag[DRONE_6_ID] = True

                            #Save the first packet
                            first_packet_timestamps[DRONE_6_ID] = relative_timestamp_ms
                        else:
                            last_packet_timestamps[DRONE_6_ID] = relative_timestamp_ms

                    else:
                        
                        last_rounds[DRONE_6_ID] = packet_round
                        last_packet_timestamps[DRONE_6_ID] = relative_timestamp_ms
                        saved_first[DRONE_6_ID] = first_packet_timestamps[DRONE_6_ID] = relative_timestamp_ms

                    #Quantify overlap with drone 1
                    if(check_overlap_flag[DRONE_5_ID]):
                        overlap = saved_first[DRONE_6_ID] - saved_last[DRONE_5_ID]
                        saved_overlap[round_counter][DRONE_6_ID] = overlap

                        #Reset check overlap
                        check_overlap_flag[DRONE_5_ID] = False          


    print("Finished reading pcap!")

    y_data = dict()

    for round in saved_overlap.keys():

        round_data = saved_overlap[round]

        if DRONE_1_ID in round_data.keys():
            
            if DRONE_1_ID in y_data.keys():
                y_data[DRONE_1_ID].append(round_data[DRONE_1_ID])
            else:
                y_data[DRONE_1_ID] = list()
                y_data[DRONE_1_ID].append(round_data[DRONE_1_ID])
        else:

            if DRONE_1_ID in y_data.keys():
                y_data[DRONE_1_ID].append(0)
            else:
                y_data[DRONE_1_ID] = list()
                y_data[DRONE_1_ID].append(0)


        if DRONE_2_ID in round_data.keys():
            
            if DRONE_2_ID in y_data.keys():
                y_data[DRONE_2_ID].append(round_data[DRONE_2_ID])
            else:
                y_data[DRONE_2_ID] = list()
                y_data[DRONE_2_ID].append(round_data[DRONE_2_ID])

        else:

            if DRONE_2_ID in y_data.keys():
                y_data[DRONE_2_ID].append(0)
            else:
                y_data[DRONE_2_ID] = list()
                y_data[DRONE_2_ID].append(0)

        if DRONE_3_ID in round_data.keys():
            
            if DRONE_3_ID in y_data.keys():
                y_data[DRONE_3_ID].append(round_data[DRONE_3_ID])
            else:
                y_data[DRONE_3_ID] = list()
                y_data[DRONE_3_ID].append(round_data[DRONE_3_ID])

        else:

            if DRONE_3_ID in y_data.keys():
                y_data[DRONE_3_ID].append(0)
            else:
                y_data[DRONE_3_ID] = list()
                y_data[DRONE_3_ID].append(0)

        if DRONE_4_ID in round_data.keys():
            
            if DRONE_4_ID in y_data.keys():
                y_data[DRONE_4_ID].append(round_data[DRONE_4_ID])
            else:
                y_data[DRONE_4_ID] = list()
                y_data[DRONE_4_ID].append(round_data[DRONE_4_ID])

        else:

            if DRONE_4_ID in y_data.keys():
                y_data[DRONE_4_ID].append(0)
            else:
                y_data[DRONE_4_ID] = list()
                y_data[DRONE_4_ID].append(0)

        if DRONE_5_ID in round_data.keys():
            
            if DRONE_5_ID in y_data.keys():
                y_data[DRONE_5_ID].append(round_data[DRONE_5_ID])
            else:
                y_data[DRONE_5_ID] = list()
                y_data[DRONE_5_ID].append(round_data[DRONE_5_ID])

        else:

            if DRONE_5_ID in y_data.keys():
                y_data[DRONE_5_ID].append(0)
            else:
                y_data[DRONE_5_ID] = list()
                y_data[DRONE_5_ID].append(0)

        if DRONE_6_ID in round_data.keys():

            if DRONE_6_ID in y_data.keys():
                y_data[DRONE_6_ID].append(round_data[DRONE_6_ID])
            else:
                y_data[DRONE_6_ID] = list()
                y_data[DRONE_6_ID].append(round_data[DRONE_6_ID])

        else:

            if DRONE_6_ID in y_data.keys():
                y_data[DRONE_6_ID].append(0)
            else:
                y_data[DRONE_6_ID] = list()
                y_data[DRONE_6_ID].append(0)

    print('Done!')

    plt.figure(figsize=(30,20))

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_1_ID], marker='o', linestyle='-', color=node_colors[DRONE_1_ID], label = "Drone 1")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-1.png')

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_2_ID], marker='o', linestyle='-', color=node_colors[DRONE_2_ID], label = "Drone 2")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-2.png')

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_3_ID], marker='o', linestyle='-', color=node_colors[DRONE_3_ID], label = "Drone 3")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-3.png')

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_4_ID], marker='o', linestyle='-', color=node_colors[DRONE_4_ID], label = "Drone 4")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-4.png')

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_5_ID], marker='o', linestyle='-', color=node_colors[DRONE_5_ID], label = "Drone 5")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-5.png')

    plt.clf()
    plt.plot(saved_overlap.keys(), y_data[DRONE_6_ID], marker='o', linestyle='-', color=node_colors[DRONE_6_ID], label = "Drone 6")
    plt.legend()
    plt.grid()
    plt.xlabel("Round Number")
    plt.ylabel("Overlap Length (ms) ")
    plt.savefig('./' + TEST_NAME +'/' + TEST_TYPE + '/' + 'slot-overlap-6.png')





if __name__ == '__main__':

    #process_pcap('./' + TEST_NAME +'/' + TEST_TYPE + '/' + TRACE_NAME)

    compute_overlap('./' + TEST_NAME +'/' + TEST_TYPE + '/' + TRACE_NAME)

