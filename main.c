#include "tun.h"
#include "trace.h"
#include "log.h"
#include "main.h"
#include "inline.h"
#include <errno.h>
#include <string.h>
#include <netinet/ether.h>

void help(char *me) {
    fprintf(stderr, "usage: %s -T -p PATHDEF_FILE -t TUN_IFNAME\n", me);
    fprintf(stderr, "usage: %s -I -p PATHDEF_FILE -i IN_IFNAME -o OUT_IFNAME -d DST_MAC\n", me);
    fprintf(stderr, "\n");
    fprintf(stderr, "modes:\n");
    fprintf(stderr, " -T: tun mode - traffic needs to be routed into the tun interface.\n");
    fprintf(stderr, " -I: inline mode - sniff low-ttl traffic from IN_IFNAME, and sends reply to DST_MAC on OUT_IFNAME.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "PATHDEF file format:\n");
    fprintf(stderr, "  hop-1-ip LABEL_1[,LABEL_2[,LABEL_N ...]]\n");
    fprintf(stderr, "  hop-2-ip LABEL_1[,LABEL_2[,LABEL_N ...]]\n");
    fprintf(stderr, "  ...\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "where the format of LABEL_* is:\n");
    fprintf(stderr, "  label:exp:s:ttl\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "for example, this file:\n");
    fprintf(stderr, "  192.0.2.1 114:0:0:11,514:0:0:51,1919:0:0:191,810:0:1:81\n");
    fprintf(stderr, "  192.0.2.2 114:0:0:11,514:0:0:51,1919:0:0:191,810:0:1:81\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "generates this traceroute:\n");
    fprintf(stderr, " 1  192.0.2.1 (192.0.2.1) <MPLS:L=114,E=0,S=0,T=11/L=514,E=0,S=0,T=51/L=1919,E=0,S=0,T=191/L=810,E=0,S=1,T=81>  0.124 ms  0.116 ms  0.114 ms\n");
    fprintf(stderr, " 2  192.0.2.2 (192.0.2.2) <MPLS:L=114,E=0,S=0,T=11/L=514,E=0,S=0,T=51/L=1919,E=0,S=0,T=191/L=810,E=0,S=1,T=81>  0.112 ms  0.109 ms  0.108 ms\n");
}

int main(int argc, char **argv) {
    int mode = MODE_UNDEF;
    uint8_t dst_mac[ETH_ALEN];
    char tunifname[IFNAMSIZ];
    char inifname[IFNAMSIZ];
    char outifname[IFNAMSIZ];
    char *pathdef_file = NULL;

    int opt;
    int iif_set = 0, oif_set = 0, tif_set = 0, dmac_set = 0;

    while ((opt = getopt(argc, argv, "Tp:t:Ii:o:d:")) != -1) {
        switch (opt) {
            case 'T':
                mode = MODE_TUN;
                break;
            case 'p':
                pathdef_file = optarg;
                break;
            case 't':
                tif_set = 1;
                strncpy(tunifname, optarg, IFNAMSIZ);
                break;
            case 'I':
                mode = MODE_INLINE;
                break;
            case 'i':
                iif_set = 1;
                strncpy(inifname, optarg, IFNAMSIZ);
                break;
            case 'o':
                oif_set = 1;
                strncpy(outifname, optarg, IFNAMSIZ);
                break;
            case 'd':
                dmac_set = 1;
                memcpy(dst_mac, ether_aton(optarg), ETH_ALEN);
                break;
            default:
                help(argv[0]);
                break;
        }
    }

    size_t nhops;
    hop_t *hops;

    if (pathdef_file == NULL) {
        help(argv[0]);
        return 1;
    }

    if (load_config(pathdef_file, &hops, &nhops) < 0) {
        return 1;
    }

    if (mode == MODE_TUN) {
        if (!tif_set) {
            help(argv[0]);
            return 1;
        }

        log_info("starting tun mode on interface %s\n", tunifname);
        tun_run(tunifname, hops, nhops);
    } else if (mode == MODE_INLINE) {
        if (!iif_set || !oif_set || !dmac_set) {
            help(argv[0]);
            return 1;
        }

        log_info("starting inline mode: in interface %s, out interface %s, target mac: %s\n", inifname, outifname, ether_ntoa((struct ether_addr *) dst_mac));

        inline_run(inifname, outifname, dst_mac, hops, nhops);
    } else {
        help(argv[0]);
    }

    return 1;
}