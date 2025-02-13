#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_NODES 20
#define MAX_AGE 30000000000

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE sizeof(struct ratdma_packet_annotations) + 2
#define TDMA_DATA_IP_OPT_PADDING (TDMA_DATA_IP_OPT_SIZE - (intdiv(TDMA_DATA_IP_OPT_SIZE, 4) * 4))
#define TDMA_DATA_IP_OPT_TOTAL_SIZE (TDMA_DATA_IP_OPT_SIZE + TDMA_DATA_IP_OPT_PADDING)

static s64 udp_broadcast_port = 0;

struct topology_info_t {
    
    s64 myID;
    s64 activeNodes;
    uint8_t connectionMatrix[MAX_NODES][MAX_NODES];
    s64 activeNodesList[MAX_NODES];
    s64 creationTime[MAX_NODES];
    s64 age[MAX_NODES];
    uint8_t active; 

};

struct ratdma_packet_annotations {

    s64 transmission_offset;    //Amount of time in ns from the start of the slot, to the moment the packet was sent
    s64 slot_id;                //ID of the slot used by the node to transmit the packet
    s64 node_id;                //ID of the node who transmitted the packet
};

static struct nf_hook_ops *nfho = NULL;

static struct topology_info_t *topology_info = NULL;

/* Called when a packet containing topology info is received */
void topology_parse(struct topology_info_t *topology_info_new) {

    printk(KERN_DEBUG "Parsing topology packet, %lld ---- %lld\n", topology_info->myID, topology_info->activeNodes);

    //Check if received packet is not mine for some reason
    if(topology_info->myID != topology_info_new->myID){

        //Check if im aware of new guy
        if(!topology_info->activeNodesList[topology_info_new->myID]){

            //If not aware: 
            
            //Activate flag
            topology_info->activeNodesList[topology_info_new->myID] = 1;

            //Increment activeNode counter
            topology_info->activeNodes++;

            //Update connection matrix
            topology_info->connectionMatrix[topology_info->myID][topology_info_new->myID] = 1;
            topology_info->connectionMatrix[topology_info_new->myID][topology_info->myID] = 1;

        }

        //Update creation time
        s64 epoch = ktime_get_real_ns();
        topology_info->creationTime[topology_info_new->myID]= epoch - topology_info_new->age[topology_info_new->myID];

        //For each node new guy has on his connection matrix, check info age. If more recent, update my connection matrix

        //For each node new guy is aware of:
        for (size_t i = 0; i < MAX_NODES; i++) {
            
            if(topology_info_new->activeNodesList[i]){

                //Check if information is more recent
                epoch = ktime_get_real_ns();
                s64 creation_time_new = epoch - topology_info_new->age[i];

                if(creation_time_new > topology_info->creationTime[i]){

                    //Information is more recent, update it

                    //Update corresponding line on ConnectionMatrix
                    for (size_t j = 0; j < MAX_NODES; j++) {
                        topology_info->connectionMatrix[i][j]=topology_info_new->connectionMatrix[i][j];
                    }

                    //Check if already aware of node and update accordingly
                    if(!topology_info->activeNodesList[i]){
                        topology_info->activeNodesList[i] = 1;
                        topology_info->activeNodes++;
                    }

                    //Update creation time
                    topology_info->creationTime[i] = creation_time_new;

                }

                //Else, information is older. Discard it.

            }

        }
        

    }

}

static void parseIPOptions(struct ratdma_packet_annotations* annotations){

    printk(KERN_DEBUG "[TOPOLOGY] SLOT_ID: %lld\n", annotations->slot_id);
    printk(KERN_DEBUG "[TOPOLOGY] NODE_ID: %lld\n", annotations->node_id);
    printk(KERN_DEBUG "[TOPOLOGY] TRANSMISSION_OFFSET: %lld\n", annotations->transmission_offset);

}

//Runs for every received packet
static unsigned int hookFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct udphdr *udph;

    //Only handle packets if topology module is being used
    if(topology_info->active){

        if(!skb) {
            return NF_ACCEPT;
        }

        //Get IP Header
        iph = ip_hdr(skb);
        if (!iph) {
            return NF_ACCEPT;
        }

        //For every packet, check if it has TDMA IPv4 Options
        if(iph->ihl > 5){

            //Packet contains options, check type.
            unsigned char* opts = (unsigned char*)(iph + 1); //Start of options field

            if(opts[0] == TDMA_DATA_IP_OPT_TYPE){
                //TDMA Options are present. Parse them
                parseIPOptions((struct ratdma_packet_annotations*) (opts + 2));
            }

        }

        //If payload is UDP, get UDP header
        if (iph->protocol == IPPROTO_UDP) {
            udph = udp_hdr(skb);
            if (!udph) {
                return NF_ACCEPT;
            }

            uint16_t dst_port = ntohs(udph->dest);

            //Check if port is expected topology port
            if(dst_port == udp_broadcast_port){

                // Calculate payload start and length
                unsigned char *udp_payload = (unsigned char *)((unsigned char *)udph + sizeof(struct udphdr)); //Pointer to the start of UDP payload
                int udp_payload_length = ntohs(udph->len) - sizeof(struct udphdr);

                if (udp_payload_length > 0 && skb_tail_pointer(skb) >= udp_payload + udp_payload_length) {
                    
                    //If this is true, most likely packet contains topology info. Parse it.
                    if(udp_payload_length == sizeof(struct topology_info_t)) {

                        struct topology_info_t *topology_temp = (struct topology_info_t *) udp_payload;

                        topology_parse(topology_temp);
                        
                        //Drop packet after processing to not bother application layer
                        return NF_DROP;

                    }

                }

            }

        }

    }

    return NF_ACCEPT; //Accept the packet regardless

}

// Called by TDMA QDisc to enable topology tracking
void topology_enable(s64 nodeID, s64 broadcast_port) {


    if(topology_info->active == 0){

        topology_info->myID = nodeID;

        topology_info->activeNodes = topology_info->activeNodes + 1;
        topology_info->activeNodesList[nodeID] = 1;

        topology_info->age[nodeID] = 0;
        s64 epoch = ktime_get_real_ns();
        topology_info->creationTime[nodeID] = epoch;

        //Activate traking (Join the network)
        topology_info->active = 1;

        //Save the port being used
        udp_broadcast_port = broadcast_port;

    }

}

uint8_t topology_is_active(void) {
    return topology_info->active;
}

//TODO: Remove. Just for debugging
void print_struct(void) {

    printk(KERN_DEBUG "id: %lld\n", topology_info->myID);
    printk(KERN_DEBUG "activeNodes: %lld\n", topology_info->activeNodes);
    
    for (size_t i = 0; i < MAX_NODES; i++) {

        printk(KERN_DEBUG "Connection Line: ");

        for (size_t j = 0; j < MAX_NODES; j++){
            printk(KERN_DEBUG "%u\n", topology_info->connectionMatrix[i][j]);
        }
        printk(KERN_DEBUG "\n");
    }

    for (size_t i = 0; i < MAX_NODES; i++) {
        printk(KERN_DEBUG "%lld\n", topology_info->activeNodesList[i]);
    }

    printk(KERN_DEBUG "\n");

    for (size_t i = 0; i < MAX_NODES; i++) {
        printk(KERN_DEBUG "%lld\n", topology_info->creationTime[i]);
    }

    printk(KERN_DEBUG "\n");

    for (size_t i = 0; i < MAX_NODES; i++) {
        printk(KERN_DEBUG "%lld\n", topology_info->age[i]);
    }

    printk(KERN_DEBUG "\n");

    printk(KERN_DEBUG "%u\n", topology_info->active);  

}

/* Called by TDMA QDisc to send topology info to the network */
void* topology_get_info(void) {

    s64 epoch = ktime_get_real_ns();

    //Update age values and discard old information
    for (size_t i = 0; i < MAX_NODES; i++) {
        
        if(i != topology_info->myID && topology_info->creationTime[i] != 0){

            s64 age = epoch - topology_info->creationTime[i]; //Nanoseconds

            printk(KERN_DEBUG "ID----Age: %d----%lld\n", i, age);

            if(age > MAX_AGE){
                
                //Discard data and set new creation time.
                topology_info->activeNodes--;
                topology_info->activeNodesList[i] = 0;
                for (size_t j = 0; j < MAX_NODES; j++) {
                    topology_info->connectionMatrix[i][j] = 0;
                }

                topology_info->connectionMatrix[topology_info->myID][i] = 0;
                
                //Update creation time and age to send
                topology_info->creationTime[i] = 0;
                topology_info->age[i] = 0;

            } else {
                //Just send age as is
                topology_info->age[i] = age;
            }

        } else {
            topology_info->age[i] = 0;
        }

    }
    
    return (void*) topology_info; 
}

size_t topology_get_info_size(void) {
    return sizeof(struct topology_info_t);
}

s64 topology_get_network_size(void) {
    return topology_info->activeNodes;
}

/* Companion function for QuickSort algorithm */
static void swapper(s64 *a, s64 *b) {
    s64 temp = *a;
    *a = *b;
    *b = temp;
}

/* Companion function for QuickSort algorithm */
static s64 partition(s64 arr[], s64 low, s64 high){
    
    s64 p = arr[low];
    s64 i = low;
    s64 j = high;

    while (i < j) {

        while (arr[i] <= p && i <= high - 1) {
            i++;
        }

        while (arr[j] > p && j >= low + 1) {
            j--;
        }
        if (i < j) {
            swapper(&arr[i], &arr[j]);
        }
    }
    swapper(&arr[low], &arr[j]);
    return j;
}

/* Helper function to sort active IDs array - QuickSort from https://www.geeksforgeeks.org/quick-sort-in-c/ */
static void quicksort(s64 arr[], s64 low, s64 high) {

    if (low < high) {

        int pi = partition(arr, low, high);

        quicksort(arr, low, pi - 1);
        quicksort(arr, pi + 1, high);

    }

}

int topology_get_slot_id(void) {

    s64 activeNodeIDS[topology_info->activeNodes];
    int foundNodes = 0;

    //Get all currently active nodes
    for (int i = 0; i < MAX_NODES; i++) {
        
        if(topology_info->activeNodesList[i]){
            activeNodeIDS[foundNodes] = i;
            foundNodes++;
        }

    }

    //Sort the active node list by ascending ID
    s64 n = sizeof(activeNodeIDS) / sizeof(activeNodeIDS[0]);
    quicksort(activeNodeIDS, 0, n - 1);

    //Find my ID in the list, and return slot position
    for (int i = 0; i < topology_info->activeNodes; i++) {
        
        s64 currentID = activeNodeIDS[i];

        if(currentID == topology_info->myID) {
            return i;
        }
    }

    return -1;
    
}

static int __init topology_init(void) {

    printk(KERN_DEBUG "TOPOLOGY: Tracker initialized.\n");

    //Initialize netfilter hook
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho->hook = (nf_hookfn*) hookFunc;     //Hook function
    nfho->hooknum = NF_INET_PRE_ROUTING;    //Incoming packets. Pre-Routing.
    nfho->pf = PF_INET;                     //Protocol to capture. IPv4
    nfho->priority = NF_IP_PRI_FIRST;

    //Initialize topology info struct
    topology_info = (struct topology_info_t*)kcalloc(1, sizeof(struct topology_info_t), GFP_KERNEL);

    topology_info->myID = 0;
    topology_info->activeNodes = 0;
    topology_info->active = 0;
    
    return nf_register_net_hook(&init_net, nfho);

}

static void __exit topology_exit(void) {

    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
    kfree(topology_info);

    printk(KERN_DEBUG "TOPOLOGY: Tracker disabled.\n");

}

EXPORT_SYMBOL_GPL(topology_enable);
EXPORT_SYMBOL_GPL(topology_get_info);
EXPORT_SYMBOL_GPL(topology_get_info_size);
EXPORT_SYMBOL_GPL(topology_get_network_size);
EXPORT_SYMBOL_GPL(topology_get_slot_id);
EXPORT_SYMBOL_GPL(topology_is_active);

module_init(topology_init);
module_exit(topology_exit);
MODULE_LICENSE("GPL");