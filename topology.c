#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;

//Runs for every received packet
static unsigned int hookFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct udphdr *udph; //Might not need

    if(!skb) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    //Do whathever with IP Header info

    printk(KERN_DEBUG "TOPOLOGY: Packet received!!");

    return NF_ACCEPT; //Accept the packet regardless

}

static int __init topology_init(void) {

    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    //Initialize netfilter hook
    nfho->hook = (nf_hookfn*) hookFunc; //Hook function
    nfho->hooknum = NF_INET_PRE_ROUTING; //Incoming packets. Pre-Routing.
    nfho->pf = PF_INET; //Protocol to capture. IPv4
    nfho->priority = NF_IP_PRI_FIRST; 

    return nf_register_net_hook(&init_net, nfho);

}

static void __exit topology_exit(void) {

    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);

}

module_init(topology_init);
module_exit(topology_exit);
MODULE_LICENSE("GPL");