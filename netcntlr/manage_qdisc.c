#include <stdio.h>
#include <stdlib.h>
#include <linux/pkt_sched.h>
#include <librtnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <net/if.h>
#include <manage_qdisc.h>

struct rtnl_handle rth;

static int qdisc_add(int cmd, unsigned int flags, struct tc_tdma_qopt *opt) {
    
    char *k = "tdma";
    int dev_index = if_nametoindex("wlo1");
    //int dev_index = if_nametoindex("enp0s2");

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
	    char buf[64 * 1024];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags,
        .n.nlmsg_type = cmd,
        .t.tcm_family = AF_UNSPEC, // unsigned char
        .t.tcm_parent = TC_H_ROOT, // __u32
    };

    struct rtattr *tail;

    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k) + 1);

    // Add TCA_OPTIONS
    tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    addattr_l(&req.n, 1024, TCA_TDMA_PARMS, opt, sizeof(*opt));
    addattr_nest_end(&req.n, tail);

    req.t.tcm_ifindex = dev_index;

    if (rtnl_talk(&rth, &req.n, NULL) < 0)
        return -1;
        
    return 0;
}

int main() {

    struct tc_tdma_qopt *opt=malloc(sizeof(struct tc_tdma_qopt));
    memset(opt, 0, sizeof(*opt));

    //options
    opt->t_frame = 10000000000;
    opt->t_slot = 5000000000;
    opt->t_offset = 0;

    if(rtnl_open(&rth, 0) < 0) {
        printf("Failed to open rtnl");
    } 

    if (qdisc_add(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, opt)) {
                    printf("Failed to add qdisc\n");
                    exit(1);
    }

    rtnl_close(&rth);

}
