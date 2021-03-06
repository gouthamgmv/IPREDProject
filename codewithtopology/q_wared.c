#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "tc_util.h"

#include "tc_red.h"
#define MAX_MSG 16384
//#include <pkt_sched.h>
//#include <pkt_cls.h>
#include <linux/gen_stats.h>
#include "tc_core.h"

enum {
    TCA_NRED_UNSPEC,
    TCA_NRED_PARMS,
    TCA_NRED_STAB,
    TCA_NRED_MAX_P,
    __TCA_NRED_MAX,
};

#define TCA_NRED_MAX (__TCA_NRED_MAX - 1)

struct tc_nred_qopt {
    __u32        limit;        /* HARD maximal queue length (bytes)    */
    __u32        qth_min;    /* Min average length threshold (bytes) */
    __u32        qth_max;    /* Max average length threshold (bytes) */
    unsigned char   Wlog;        /* log(W)        */
    unsigned char   Plog;        /* log(P_max/(qth_max-qth_min))    */
    unsigned char   Scell_log;    /* cell size for idle damping */
    unsigned char    flags;
    __u32         factor;
};



struct tc_nred_xstats {
    __u32           early;          /* Early drops */
    __u32           pdrop;          /* Drops due to queue limits */
    __u32           other;          /* Drops due to drop() calls */
    __u32           marked;         /* Marked packets */
};


int toString(char a[]) {
  int c, sign, offset, n;
 
  if (a[0] == '-') {  // Handle negative integers
    sign = -1;
  }
 
  if (sign == -1) {  // Set starting position to convert
    offset = 1;
  }
  else {
    offset = 0;
  }
 
  n = 0;
 
  for (c = offset; a[c] != '\0'; c++) {
    n = n * 10 + a[c] - '0';
  }
 
  if (sign == -1) {
    n = -n;
  }
 
  return n;
}

static void explain(void)
{
    fprintf(stderr, "Usage: ... wared limit BYTES [min BYTES] [max BYTES] avpkt BYTES [burst PACKETS]\n");
    fprintf(stderr, "               [probability PROBABILITY] \n");
}

static int red_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
    struct tc_nred_qopt opt;
    unsigned burst = 0;
    unsigned avpkt = 0;
    double probability = 0.02;
    unsigned rate = 0;
    int wlog;
    char a[10];
    int len,i,result;
   
    __u8 sbuf[256];
    __u32 max_P;
    struct rtattr *tail;

    memset(&opt, 0, sizeof(opt));

    while (argc > 0) {
        if (strcmp(*argv, "limit") == 0) {
            NEXT_ARG();
            if (get_size(&opt.limit, *argv)) {
                fprintf(stderr, "Illegal \"limit\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "min") == 0) {
            NEXT_ARG();
            if (get_size(&opt.qth_min, *argv)) {
                fprintf(stderr, "Illegal \"min\"\n");
                return -1;
            }
        }else if (strcmp(*argv, "factor") == 0) {
            NEXT_ARG();
            strcpy(a,*argv);
           
        len = strlen(a);

        for(i=0; i<len; i++){

            result = result * 10 + ( a[i] - '0' );

                }
               
            opt.factor=result;
            //fprintf(stderr, "Illegal \"decre\ %d\n",opt.decrement);
                //return -1;
           
        }
        else if (strcmp(*argv, "max") == 0) {
            NEXT_ARG();
            if (get_size(&opt.qth_max, *argv)) {
                fprintf(stderr, "Illegal \"max\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "burst") == 0) {
            NEXT_ARG();
            if (get_unsigned(&burst, *argv, 0)) {
                fprintf(stderr, "Illegal \"burst\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "avpkt") == 0) {
            NEXT_ARG();
            if (get_size(&avpkt, *argv)) {
                fprintf(stderr, "Illegal \"avpkt\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "probability") == 0) {
            NEXT_ARG();
            if (sscanf(*argv, "%lg", &probability) != 1) {
                fprintf(stderr, "Illegal \"probability\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "bandwidth") == 0) {
            NEXT_ARG();
            if (get_rate(&rate, *argv)) {
                fprintf(stderr, "Illegal \"bandwidth\"\n");
                return -1;
            }
        }  else if (strcmp(*argv, "help") == 0) {
            explain();
            return -1;
        } else {
            fprintf(stderr, "What is \"%s\"?\n", *argv);
            explain();
            return -1;
        }
        argc--; argv++;
    }
	opt.flags |= TC_RED_ADAPTATIVE;
    if (rate == 0)
        get_rate(&rate, "10Mbit");

    if (!opt.limit || !avpkt) {
        fprintf(stderr, "WARED: Required parameter (limit, avpkt) is missing\n");
        return -1;
    }
    /* Compute default min/max thresholds based on
     * Sally Floyd's recommendations:
     * http://www.icir.org/floyd/REDparameters.txt
     */
    if (!opt.qth_max)
        opt.qth_max = opt.qth_min ? opt.qth_min * 3 : opt.limit / 4;
    if (!opt.qth_min)
        opt.qth_min = opt.qth_max / 3;
    if (!burst)
        burst = (2 * opt.qth_min + opt.qth_max) / (3 * avpkt);
    if ((wlog = tc_red_eval_ewma(opt.qth_min, burst, avpkt)) < 0) {
        fprintf(stderr, "WARED: failed to calculate EWMA constant.\n");
        return -1;
    }
    if (wlog >= 10)
        fprintf(stderr, "WARED: WARNING. Burst %d seems to be too large.\n", burst);
    opt.Wlog = wlog;
    if ((wlog = tc_red_eval_P(opt.qth_min, opt.qth_max, probability)) < 0) {
        fprintf(stderr, "WARED: failed to calculate probability.\n");
        return -1;
    }
    opt.Plog = wlog;
   
    if ((wlog = tc_red_eval_idle_damping(opt.Wlog, avpkt, rate, sbuf)) < 0) {
        fprintf(stderr, "WARED: failed to calculate idle damping table.\n");
        return -1;
    }
    opt.Scell_log = wlog;
    //opt.decrement=opt.qth_min/10;
    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(n, 1024, TCA_NRED_PARMS, &opt, sizeof(opt));
    addattr_l(n, 1024, TCA_NRED_STAB, sbuf, 256);
    max_P = probability * pow(2, 32);
    addattr_l(n, 1024, TCA_NRED_MAX_P, &max_P, sizeof(max_P));
    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
    return 0;
}


static int red_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
    struct rtattr *tb[TCA_NRED_MAX + 1];
    struct tc_nred_qopt *qopt;
    __u32 max_P = 0;
    SPRINT_BUF(b1);
    SPRINT_BUF(b2);
    SPRINT_BUF(b3);
    //SPRINT_BUF(b4);

    if (opt == NULL)
        return 0;

    parse_rtattr_nested(tb, TCA_NRED_MAX, opt);

    if (tb[TCA_NRED_PARMS] == NULL)
        return -1;
    qopt = RTA_DATA(tb[TCA_NRED_PARMS]);
    if (RTA_PAYLOAD(tb[TCA_NRED_PARMS])  < sizeof(*qopt))
        return -1;

    if (tb[TCA_NRED_MAX_P] &&
        RTA_PAYLOAD(tb[TCA_NRED_MAX_P]) >= sizeof(__u32))
        max_P = rta_getattr_u32(tb[TCA_NRED_MAX_P]);

    fprintf(f, "limit %s min %s max %s ",
        sprint_size(qopt->limit, b1),
        sprint_size(qopt->qth_min, b2),
        sprint_size(qopt->qth_max, b3));
        //sprint_size(qopt->decrement, b4));
    if (qopt->flags & TC_RED_ECN)
        fprintf(f, "ecn ");
    if (qopt->flags & TC_RED_HARDDROP)
        fprintf(f, "harddrop ");
    if (qopt->flags & TC_RED_ADAPTATIVE)
        fprintf(f, "adaptive ");
    if (show_details) {
        fprintf(f, "ewma %u ", qopt->Wlog);
        if (max_P)
            fprintf(f, "probability %lg ", max_P / pow(2, 32));
        else
            fprintf(f, "Plog %u ", qopt->Plog);
        fprintf(f, "Scell_log %u", qopt->Scell_log);
    }
    return 0;
}

static int red_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{

    return 0;
}


struct qdisc_util wared_qdisc_util = {
    .id        = "wared",
    .parse_qopt    = red_parse_opt,
    .print_qopt    = red_print_opt,
    .print_xstats    = red_print_xstats,
};

