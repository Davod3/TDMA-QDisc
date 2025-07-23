/*

This file contains constants and structs used for synchronizaion both by the <ratdma> and <topology> modules.

*/


//THIS STRUCT MUST NOT EXCEED 40 BYTES (MAX IP OPTIONS LENGTH)
struct ratdma_packet_annotations {

    s64 transmission_offset;    //Amount of time in ns from the start of the slot, to the moment the packet was sent
    s64 slot_id;                //ID of the slot used by the node to transmit the packet
    s64 node_id;                //ID of the node who transmitted the packet
	s64 slot_number;				//Sequential number of slots used so far
};

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE sizeof(struct ratdma_packet_annotations) + 2
#define TDMA_DATA_IP_OPT_PADDING (TDMA_DATA_IP_OPT_SIZE - (intdiv(TDMA_DATA_IP_OPT_SIZE, 4) * 4))
#define TDMA_DATA_IP_OPT_TOTAL_SIZE (TDMA_DATA_IP_OPT_SIZE + TDMA_DATA_IP_OPT_PADDING)

#define MAX_NODES 20
#define MAX_DELAYS 5000

struct ratdma_packet_delays {

    s64 node_delays[MAX_NODES][MAX_DELAYS];
    s64 delay_counters[MAX_NODES];

};