#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_NODES 20

struct topology_info_t {
    
    s64 myID;
    s64 activeNodes;
    uint8_t connectionMatrix[MAX_NODES][MAX_NODES];
    s64 activeNodesList[MAX_NODES];
    s64 creationTime[MAX_NODES];
    s64 age[MAX_NODES];
    uint8_t active; 

};

static struct nf_hook_ops *nfho = NULL;

static struct topology_info_t *topology_info = NULL;

//Runs for every received packet
static unsigned int hookFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;

    if(!skb) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    //Do whathever with IP Header info

    if(topology_info->active){
        //printk(KERN_DEBUG "TOPOLOGY: Packet received, processing...\n");
    } else {
        //printk(KERN_DEBUG "TOPOLOGY: Packet received, but ignored.\n");
    }

    return NF_ACCEPT; //Accept the packet regardless

}

// Called by TDMA QDisc to enable topology tracking
void topology_enable(s64 nodeID) {


    if(topology_info->active == 0){

        topology_info->myID = nodeID;

        topology_info->activeNodes = topology_info->activeNodes + 1;
        topology_info->activeNodesList[topology_info->activeNodes - 1] = nodeID;

        topology_info->age[nodeID] = 0;
        s64 epoch = ktime_get_real_ns();
        topology_info->creationTime[nodeID] = epoch;

        //Activate traking (Join the network)
        topology_info->active = 1;

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

    //print_struct();

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

    //Get all currently active nodes
    for (int i = 0; i < topology_info->activeNodes; i++) {
        
        activeNodeIDS[i] = topology_info->activeNodesList[i];

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

/* Called when a packet containing topology info is received */
void topology_parse(void) {

    //TODO

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