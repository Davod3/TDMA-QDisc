#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <malloc.h>

#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <libnetlink.h>

#include "tc_tdma.h"

struct rtnl_handle rth; 

static int qdisc_modify(int cmd, unsigned int flags, struct tc_tdma_qopt *opt) {
    // cmd = RTM_NEWQDISC // add | change | replace | link
    // cmd = RTM_DELQDISC // delete
    // flags = NLM_F_EXCL | NLM_F_CREATE // add 
    // flags = 0 // change | delete
    // flags = NLM_F_CREATE | NLM_F_REPLACE // replace
    // flags = NLM_F_REPLACE // link

    // char d[IFNAMSIZ] = {};
    char d[16] = {}; // device (interface) name 
    // char k[FILTER_NAMESZ] = {};
    char k[16] = {}; // qdisc (kind) name

    struct {
        struct nlmsghdr n;
        struct tcmsg t; 
        char buf[64 * 1024];
        // char buf[TCA_BUF_MAX];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags, 
        .n.nlmsg_type = cmd,

        .t.tcm_family = AF_UNSPEC, // unsigned char
        // .t.tcm_ifindex // int // required
        // .t.tcm_handle = handle, // __u32 // optional
        .t.tcm_parent = TC_H_ROOT, // __u32
        // .t.tcm_info = 0 // __u32 // optional 
    };

    struct rtattr *tail;

    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k));

    // Add TCA_OPTIONS
    tail = addattr_nest(&req.n, 2048, TCA_OPTIONS);
    addattr_l(&req.n, 2048, TCA_TBF_PARMS, opt, sizeof(opt));
    addattr_nest_end(&req.n, tail);

    if (d[0]) {
        int idx;

        ll_init_map(&rth);

        idx = ll_name_to_index(d);
        if (!idx)
            return 1;
        req.t.tcm_ifindex = idx;
    }

    if (rtnl_talk(&rth, &req.n, NULL) < 0)
        return 1;
     
    return 0;
}

int main(int argc, char **argv) {
    if (rtnl_open(&rth, 0) < 0) {
        printf(stderr, "Cannot open rtnetlink\n");
        exit(1);
    }
}
