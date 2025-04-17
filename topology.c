#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h> 
#include <linux/spinlock.h>

#define MAX_NODES 20
#define MAX_AGE 30000000000
#define MAX_DELAYS 5000

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE sizeof(struct ratdma_packet_annotations) + 2
#define TDMA_DATA_IP_OPT_PADDING (TDMA_DATA_IP_OPT_SIZE - (intdiv(TDMA_DATA_IP_OPT_SIZE, 4) * 4))
#define TDMA_DATA_IP_OPT_TOTAL_SIZE (TDMA_DATA_IP_OPT_SIZE + TDMA_DATA_IP_OPT_PADDING)

#define DEFAULT_IPH_LEN 20

static s64 udp_broadcast_port = 0;
static char* qdisc_dev_name = NULL;
static s64 slot_start = 0;
static s64 slot_len = 0;
static int8_t delays_flag = 1;

struct topology_info_t {
    
    s64 myID;
    s64 activeNodes;
    uint8_t connectionMatrix[MAX_NODES][MAX_NODES];
    s64 activeNodesList[MAX_NODES];
    s64 creationTime[MAX_NODES];
    s64 age[MAX_NODES];
    uint8_t active; 

};

struct spanning_tree_t {
    uint8_t spanning_tree[MAX_NODES][MAX_NODES];
    s64 n_child_nodes[MAX_NODES];
    s64 n_nodes;
    uint8_t included_nodes[MAX_NODES];
};

struct ratdma_packet_annotations {

    s64 transmission_offset;    //Amount of time in ns from the start of the slot, to the moment the packet was sent
    s64 slot_id;                //ID of the slot used by the node to transmit the packet
    s64 node_id;                //ID of the node who transmitted the packet
    s64 slot_number				//Sequential number of slots used so far
};

struct ratdma_packet_delays {

    s64 node_delays[MAX_NODES][MAX_DELAYS];
    s64 delay_counters[MAX_NODES];

};

static struct nf_hook_ops* nfho_in = NULL;
static struct topology_info_t* topology_info = NULL;
static struct ratdma_packet_delays* ratdma_packet_delays = NULL;
static struct spanning_tree_t* spanning_tree = NULL;

//Mutexes
static DEFINE_SPINLOCK(topology_info_lock);
static DEFINE_SPINLOCK(slot_start_lock);
static DEFINE_SPINLOCK(spanning_tree_lock);
static DEFINE_SPINLOCK(packet_delays_lock);

static s64 intdiv(s64 a, u64 b) {
	return (((a * ((a >= 0) ? 1 : -1)) / b) * ((a >= 0) ? 1 : -1)) - ((!(a >= 0)) && (!(((a * ((a >= 0) ? 1 : -1)) % b) == 0)));
}

static s64 mod(s64 a, s64 b)
{
    s64 r = a % b;
    return r < 0 ? r + b : r;
}

//Companion function to update_spanning_tree to find node with minimum key value
static int minKey(int key[], bool stSet[]){

    int min = INT_MAX, min_index;

    for(int v = 0; v < MAX_NODES; v++){

        if(stSet[v] == false && key[v] < min) {
            min = key[v], min_index = v;
        }

    }

    return min_index;

}

//TODO - REMOVE
static void print_matrix(void) {

    //Print topology

    printk(KERN_DEBUG "-----------------------TOPOLOGY------------------------\n");

    for(int i = 0; i < MAX_NODES; i++) {

        printk(KERN_DEBUG "Node %d:\n", i);

        for(int j = 0; j < MAX_NODES; j++) {

            if(topology_info->connectionMatrix[i][j]){

                printk(KERN_DEBUG "%d -> %d == %d\n", i,j, topology_info->connectionMatrix[i][j]);

            }

        }

        printk(KERN_DEBUG "----------------------------------\n");
    }

    //Print spanning tree

    printk(KERN_DEBUG "-----------------------SPANNING TREE------------------------\n");

    for(int i = 0; i < MAX_NODES; i++) {

        printk(KERN_DEBUG "Node %d:\n", i);

        for(int j = 0; j < MAX_NODES; j++) {

            if(spanning_tree->spanning_tree[i][j]){

                printk(KERN_DEBUG "%d -> %d == %d\n", i,j, spanning_tree->spanning_tree[i][j]);

            }

        }

        printk(KERN_DEBUG "----------------------------------\n");
    }

}

//Spanning tree built Prim's Algorithm (https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/)
void topology_update_spanning_tree(void) {

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    //CRITICAL-ST-LOCK
    spin_lock(&spanning_tree_lock);

    //Delete previous ST
    if(spanning_tree){
        kfree(spanning_tree);
    }

    //Allocate space for new ST
    spanning_tree = (struct spanning_tree_t*)kcalloc(1, sizeof(struct spanning_tree_t), GFP_KERNEL);

    int key[MAX_NODES];
    bool stSet[MAX_NODES];

    //Start keys (weights) as largest posssible value
    for(int i = 0; i < MAX_NODES; i++) {
        key[i] = INT_MAX, stSet[i] = false;
    }

    int active_node_id = 0;

    //Get first active node
    for(int n = 0; n < MAX_NODES; n++){

        if(topology_info->activeNodesList[n]){
            active_node_id = n;
            break;
        }

    }

    //Make it first node of ST
    key[active_node_id] = 0;

    //Build ST
    for (int count = 0; count < MAX_NODES - 1; count++){

        //Get smallest key of nodes not yet in the ST (First run will be u == active_node_id)
        int u = minKey(key, stSet);

        //Add the picked node to ST
        stSet[u] = true;

        //Update adjacent nodes
        for(int v = 0; v < MAX_NODES; v++){

            //Graph[u][v] is non-zero only for adjacent nodes of u
            //stSet[v] is false for nodes not yet in the ST
            //Update the key only if graph[u][v] is smaller than key[v]
            if(topology_info->connectionMatrix[u][v] && stSet[v] == false && topology_info->connectionMatrix[u][v] < key[v]){

                //Add connection to ST and update stats
                spanning_tree->spanning_tree[u][v] = 1;
                
                //This might break things. Remove if so
                spanning_tree->spanning_tree[v][u] = 1;

                spanning_tree->n_child_nodes[u]++;

                //Update key
                key[v] = topology_info->connectionMatrix[u][v];

                //Include parent and node
                spanning_tree->included_nodes[u] = 1;
                spanning_tree->included_nodes[v] = 1;

            }

        }

    }

    //Save total number of nodes in the tree
    spanning_tree->n_nodes = topology_info->activeNodes;

    //TODO - REMOVE
    print_matrix();

    //CRITICAL-ST-UNLOCK
    spin_unlock(&spanning_tree_lock);

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

}

s64 topology_get_reference_node(void){

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    s64 id = topology_info->myID;
    
    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

    //CRITICAL-ST-LOCK
    spin_lock(&spanning_tree_lock);

    //printk(KERN_DEBUG "N_NODES_ST: %lld", spanning_tree->n_nodes);

    s64 node_levels[spanning_tree->n_nodes];
    uint8_t picked_nodes[MAX_NODES];

    //Order the nodes by level (Assumes each level will only have one node)
    //While there are still nodes left, do this
    for(int i = 0; i < spanning_tree->n_nodes; i++){

        int current_max_children = -1;
        int current_winner = id;

        //Get node with most children not yet picked
        for(int j = 0; j < MAX_NODES; j++) {

            if(spanning_tree->included_nodes[j] && !picked_nodes[j]){
                
                //printk(KERN_DEBUG "Found relevant node: %lld\n", j);

                s64 n_children = spanning_tree->n_child_nodes[j];

                //printk(KERN_DEBUG "Children Info: %lld\n", n_children, current_max_children);

                if(n_children > current_max_children){
                    current_max_children = n_children;
                    current_winner = j;
                }
            }

        }

        //printk(KERN_DEBUG "Level %d ----> Node %d\n", i, current_winner);

        node_levels[i] = current_winner;
        picked_nodes[current_winner] = 1;

    }

    s64 parent_id = id;

    //node_levels now contains info about each node in the network. Pick my parent
    for(s64 i = id - 1; i >= 0; i--){

        //Pick a parent in a higher level with whom i have a connection
        if(spanning_tree->spanning_tree[id][i]){
            parent_id = i;
            break;
        }

    }

    //CRITICAL-ST-UNLOCK
    spin_unlock(&spanning_tree_lock);

    return parent_id == id ? -1 : parent_id;

}

void topology_get_delays_and_reset(void* copy){

    //CRITICAL-DELAYS-LOCK
    spin_lock(&packet_delays_lock);

    //Copy delays to requesting module
    memcpy(copy, ratdma_packet_delays, sizeof(struct ratdma_packet_delays));

    //Reset all counters to 0
    for(int i = 0; i < MAX_NODES; i++){
        ratdma_packet_delays->delay_counters[i] = 0;
    }

    //CRITICAL-DELAYS-UNLOCK
    spin_unlock(&packet_delays_lock);


}

void topology_set_delays_flag(int value) {

    //printk(KERN_DEBUG "Set delays flag to: %d\n", value);

    if(value > 0) {
        delays_flag = 1;
        //printk("[DELAY_ON]\n");
    } else {
        delays_flag = 0;
        //printk("[DELAY_OFF]\n");
    }

}

/* Called when a packet containing topology info is received */
static void topology_parse(struct topology_info_t *topology_info_new) {

    //printk(KERN_DEBUG "Parsing topology packet, %lld ---- %lld\n", topology_info->myID, topology_info->activeNodes);

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

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
            
            //Don't let new guy gaslight me about what i know
            if(i == topology_info->myID ){
                continue;
            }

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

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

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

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

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

            //CRITICAL-TOPOLOGY-UNLOCK
            spin_unlock(&topology_info_lock);

            return i;
        }
    }

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

    return -1;
    
}

static void parseIPOptions(struct ratdma_packet_annotations* annotations, s64 packet_arrival_time){

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    s64 active_nodes = topology_info->activeNodes;

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

    s64 received_slot_id = annotations->slot_id;
    s64 received_node_id = annotations->node_id;
    s64 received_transmission_offset = annotations->transmission_offset;
    s64 slot_number = annotations->slot_number;
    s64 packet_timestamp = mod(packet_arrival_time, slot_len * active_nodes);

    if(active_nodes > 1 && delays_flag) {

        s64 frame_len = slot_len * active_nodes;

        //CRITICAL-SLOT_START-LOCK
        spin_lock(&slot_start_lock);

        //Calculate expected slot start of node who sent the packet
        s64 expected_slot_start = mod((slot_start - ((topology_get_slot_id() - received_slot_id)*slot_len) + frame_len), frame_len);

        //CRITICAL-SLOT_START-UNLOCK
        spin_unlock(&slot_start_lock);

        //Calculate expected packet arrival time
        s64 expected_packet_arrival = mod( expected_slot_start + received_transmission_offset , frame_len);

        //Calculate packet delay
        s64 packet_delay = mod((packet_timestamp - expected_packet_arrival + intdiv(frame_len, 2)), frame_len) - intdiv(frame_len, 2);
        
        //CRITICAL - DELAYS - LOCK
        spin_lock(&packet_delays_lock);

        //Get total number of delays
        s64 counter = ratdma_packet_delays->delay_counters[received_node_id];
        
        //Make sure i does not go over MAX_DELAYS
        s64 i = mod(counter, MAX_DELAYS);

        ratdma_packet_delays->node_delays[received_node_id][i] = packet_delay;
        ratdma_packet_delays->delay_counters[received_node_id]++;

        //printk(KERN_DEBUG "[DELAY] %lld | %lld | %lld | %lld | %lld\n", received_node_id, received_slot_id, packet_timestamp, packet_delay, slot_number);

        //CRITICAL - DELAYS - UNLOCK
        spin_unlock(&packet_delays_lock);

    }

    //printk(KERN_DEBUG "[RECEIVED_PACKET] %lld | %lld | %lld\n", annotations->slot_id, packet_timestamp, slot_number);

}

void topology_set_slot_start(s64 slot_start_external) {
    
    //CRITICAL-SLOT_START-LOCK
    spin_lock(&slot_start_lock);

    slot_start = slot_start_external;
    
    //CRITICAL-SLOT_START-UNLOCK
    spin_unlock(&slot_start_lock);
}

//TODO: REMOVE
static void dump_skb_data(const struct sk_buff *skb) {
    int i;
    unsigned char *data;
    int data_len;

    if (!skb)
        return;

    // Get the data pointer and length
    data = skb->data;
    data_len = skb->len;

    printk(KERN_INFO "skb data dump (len=%d bytes):\n", data_len);

    for (i = 0; i < data_len; i++) {
        // Print each byte in hex format
        printk(KERN_CONT "%02X ", data[i]);

        // Print a newline every 16 bytes for readability
        if ((i + 1) % 16 == 0)
            printk(KERN_CONT "\n");
    }

    // Print final newline if needed
    if (data_len % 16 != 0)
        printk(KERN_CONT "\n");
}


static void removeIPOptions(struct sk_buff* skb, int opt_len){

    //Pointer to start of headers
	void* skb_data_start = skb->data;
    int memory_to_move_len = DEFAULT_IPH_LEN;

    //Shift everything until end of IP Header to end of options space
    memmove(skb_data_start + opt_len, skb_data_start, memory_to_move_len);

    //Remove extra bytes
    skb_pull(skb, opt_len);

    //Reset Headers
    skb_reset_network_header(skb);

    //Set correct IP Header lengths
    struct iphdr *iph = ip_hdr(skb);
    iph->ihl = DEFAULT_IPH_LEN / 4;
    iph->tot_len = htons(ntohs(iph->tot_len) - opt_len);

    //Calculate IP checksum
	ip_send_check(iph);

}

//Runs for every packet sent
static unsigned int hookOUT(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){

    //Only handle packets if topology module is being used
    if(topology_info->active){

        if(!skb) {
            return NF_ACCEPT;
        }

        //Check if packet is IPv4
        struct iphdr* iph = ip_hdr(skb);
        if (!iph) {
            return NF_ACCEPT;
        }

        //printk(KERN_DEBUG "Outgoing packet! \n");

        //Check if packet has IPv4 Options
        if(iph->ihl > 5){

            unsigned char* opts = (unsigned char*)(iph + 1); //Start of options field

            //printk(KERN_DEBUG "Packet has options!\n");

            //Check if options are TDMA Annotations
            if(opts[0] == TDMA_DATA_IP_OPT_TYPE){

                //Check if the packet is going to an interface without the QDisc
                if (skb->dev && strcmp(skb->dev->name, qdisc_dev_name) != 0) {

                    //Make sure packet is continuous memory block
                    if (skb_linearize(skb) < 0)
                        return NF_ACCEPT;

                    //Make sure packet is writable
                    if (skb_ensure_writable(skb, skb->len))
                        return NF_ACCEPT;
                    
                    //Packet is going to different interface. Remove TDMA options from header
                    int opt_len = opts[1];
                    removeIPOptions(skb, opt_len);
                    //printk(KERN_DEBUG "Options reset! --- %d\n", skb->len);

                }

            }

        }

    }

    return NF_ACCEPT; //Allow packet to leave regardless

}

//Runs for every received packet
static unsigned int hookIN(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct udphdr *udph;

    //Only handle packets if topology module is being used
    if(topology_info->active){

        s64 packet_arrival_time = ktime_get_real_ns();

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
                parseIPOptions((struct ratdma_packet_annotations*) (opts + 2), packet_arrival_time);

                //Make sure packet is continuous memory block
                if (skb_linearize(skb) < 0)
                    return NF_ACCEPT;
                
                //Make sure packet is writable
                if (skb_ensure_writable(skb, skb->len))
                    return NF_ACCEPT;

                //Remove IP Options from header
                int opt_len = opts[1];
                removeIPOptions(skb, opt_len);
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
void topology_enable(s64 nodeID, s64 broadcast_port, char* dev_name, s64 slot_len_external) {

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

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

        //Save the interface used by the QDisc
        qdisc_dev_name = dev_name;

        //Save the len of the slots;
        slot_len = slot_len_external;

    }

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

}

uint8_t topology_is_active(void) {

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    uint8_t isActive = topology_info->active;
    
    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

    return isActive;
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

    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    s64 epoch = ktime_get_real_ns();

    //Update age values and discard old information
    for (size_t i = 0; i < MAX_NODES; i++) {
        
        if(i != topology_info->myID && topology_info->creationTime[i] != 0){

            s64 age = epoch - topology_info->creationTime[i]; //Nanoseconds

            //printk(KERN_DEBUG "ID----Age: %d----%lld\n", i, age);

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

    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);
    
    return (void*) topology_info; 
}

size_t topology_get_info_size(void) {
    return sizeof(struct topology_info_t);
}

s64 topology_get_network_size(void) {
    
    //CRITICAL-TOPOLOGY-LOCK
    spin_lock(&topology_info_lock);

    s64 network_size = topology_info->activeNodes;
    
    //CRITICAL-TOPOLOGY-UNLOCK
    spin_unlock(&topology_info_lock);

    return network_size;
}

static int __init topology_init(void) {

    printk(KERN_DEBUG "TOPOLOGY: Tracker initialized.\n");

    //Initialize netfilter hook - IN
    nfho_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nfho_in->hook = (nf_hookfn*) hookIN;     //Hook function
    nfho_in->hooknum = NF_INET_PRE_ROUTING;    //Incoming packets. Pre-Routing.
    nfho_in->pf = PF_INET;                     //Protocol to capture. IPv4
    nfho_in->priority = NF_IP_PRI_FIRST;

    //Initialize topology info struct
    topology_info = (struct topology_info_t*)kcalloc(1, sizeof(struct topology_info_t), GFP_KERNEL);

    topology_info->myID = 0;
    topology_info->activeNodes = 0;
    topology_info->active = 0;

    //Initialize ratdma delays struct
    ratdma_packet_delays = (struct ratdma_packet_delays*)kcalloc(1, sizeof(struct ratdma_packet_delays), GFP_KERNEL);

    int ret_in = nf_register_net_hook(&init_net, nfho_in);

    return ret_in;

}

static void __exit topology_exit(void) {

    //Clear incoming packet hook
    nf_unregister_net_hook(&init_net, nfho_in);
    kfree(nfho_in);

    //Clear data structures
    kfree(topology_info);
    kfree(ratdma_packet_delays);

    if(spanning_tree){
        kfree(spanning_tree);
    }

    printk(KERN_DEBUG "TOPOLOGY: Tracker disabled.\n");

}

EXPORT_SYMBOL_GPL(topology_enable);
EXPORT_SYMBOL_GPL(topology_get_info);
EXPORT_SYMBOL_GPL(topology_get_info_size);
EXPORT_SYMBOL_GPL(topology_get_network_size);
EXPORT_SYMBOL_GPL(topology_get_slot_id);
EXPORT_SYMBOL_GPL(topology_is_active);
EXPORT_SYMBOL_GPL(topology_set_slot_start);
EXPORT_SYMBOL_GPL(topology_update_spanning_tree);
EXPORT_SYMBOL_GPL(topology_get_reference_node);
EXPORT_SYMBOL_GPL(topology_get_delays_and_reset);
EXPORT_SYMBOL_GPL(topology_set_delays_flag);


module_init(topology_init);
module_exit(topology_exit);
MODULE_LICENSE("GPL");
