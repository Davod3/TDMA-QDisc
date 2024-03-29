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

#include <libnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
    // char *d = "enp0s1";
    strncpy(d, "enp0s1", 16);
    // char k[FILTER_NAMESZ] = {};
    char k[16] = {}; // qdisc (kind) name
    strncpy(k, "tdma", 16);
    // char *k = "tdma";

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

    // BEGIN hardcoding    // END hardcoding

    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k) + 1);

    // Add TCA_OPTIONS
    tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    addattr_l(&req.n, 2024, TCA_TBF_PARMS, opt, sizeof(*opt));
    addattr_nest_end(&req.n, tail);

    if (d[0]) {
        int idx;

        ll_init_map(&rth);

        idx = ll_name_to_index(d);
        if (!idx)
            return 1;
        req.t.tcm_ifindex = idx;
    printf("%d\n", idx);
    }

    if (rtnl_talk(&rth, &req.n, NULL) < 0)
        return 1;
    
    return 0;
}

struct tc_ratespec *dummy_ratespec() {
    struct tc_ratespec *rs;
    rs = malloc(sizeof(struct tc_ratespec));
    rs->cell_log = '\0';
    rs->linklayer = 0;
    rs->overhead = 0;
    rs->cell_align = 0;
    rs->mpu = 0;
    rs->rate = 0;
    return rs;
}

int main(int argc, char **argv) {
    struct tc_tdma_qopt *opt;
    struct tc_ratespec *rate;
    struct tc_ratespec *peakrate;
    


    if (rtnl_open(&rth, 0) < 0) {
        printf("Cannot open rtnetlink\n");
        exit(1);
    }

    printf("Hello, world!\n");

    opt = malloc(sizeof(struct tc_tdma_qopt));
    opt->rate = *dummy_ratespec();
    opt->rate.linklayer = 1;
    opt->rate.rate = 27500;
    opt->peakrate = *dummy_ratespec();

    opt->limit = 2915;
    opt->buffer = 874999;
    opt->mtu = 0;
    opt->frame = 1000000000;
    opt->slot = 100000000;

    if (qdisc_modify(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, opt)) {
        printf("Failed to add qdisc\n");
        exit(1);
    }

    rtnl_close(&rth);

    printf("Success\n");
    return 0;
}
