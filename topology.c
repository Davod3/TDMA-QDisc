#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_NODES 255

struct topology_info_t {
    
    uint8_t myID;
    uint8_t activeNodes;
    uint8_t connectionMatrix[MAX_NODES][MAX_NODES];
    uint8_t activeNodesList[MAX_NODES];
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
        printk(KERN_DEBUG "TOPOLOGY: Packet received, processing...\n");
    } else {
        printk(KERN_DEBUG "TOPOLOGY: Packet received, but ignored.\n");
    }

    return NF_ACCEPT; //Accept the packet regardless

}

// Called by TDMA QDisc to enable topology tracking
static void topology_enable(int nodeID) {

    topology_info->myID = nodeID;

    topology_info->activeNodes = topology_info->activeNodes + 1;
    topology_info->activeNodesList[topology_info->activeNodes - 1] = nodeID;

    topology_info->age[nodeID] = 0;
    s64 epoch = ktime_get_real_ns();
    topology_info->creationTime[nodeID] = epoch;

    //Activate traking (Join the network)
    topology_info->active = 1;

}

/* Called by TDMA QDisc to send topology info to the network */
static void topology_serialize(void) {

    //TODO

}

/* Called when a packet containing topology info is received */
static void topology_parse(void) {

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

EXPORT_SYMBOL(topology_enable);
EXPORT_SYMBOL(topology_serialize);

module_init(topology_init);
module_exit(topology_exit);
MODULE_LICENSE("GPL");