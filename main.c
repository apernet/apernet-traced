#include "tun.h"
#include "trace.h"
#include "log.h"
#include "main.h"
#include "inline.h"
#include "config.h"
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <netinet/ether.h>

void help(char *me) {
    fprintf(stderr, "usage: %s -T -p PATHDEF_FILE -t TUN_IFNAME\n", me);
    fprintf(stderr, "usage: %s -I -p PATHDEF_FILE -i IN_IFNAME -o OUT_IFNAME -d DST_MAC\n", me);
    fprintf(stderr, "\n");
    fprintf(stderr, "modes:\n");
    fprintf(stderr, " -T: tun mode - traffic needs to be routed into the tun interface.\n");
    fprintf(stderr, " -I: inline mode - sniff low-ttl traffic from IN_IFNAME, and sends reply to\n");
    fprintf(stderr, "     DST_MAC on OUT_IFNAME.\n");
}

int main(int argc, char **argv) {
    int mode = MODE_UNDEF;
    uint8_t dst_mac[ETH_ALEN];
    char tunifname[IFNAMSIZ + 1];
    char inifname[IFNAMSIZ + 1];
    char outifname[IFNAMSIZ + 1];
    char *pathdef_file = NULL;

    // to be used by various rand values
    srand(time(NULL));

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

    rule_t *rules;

    if (pathdef_file == NULL) {
        help(argv[0]);
        return 1;
    }

    if (parse_rules(pathdef_file, &rules) < 0) {
        return 1;
    }

    if (mode == MODE_TUN) {
        if (!tif_set) {
            help(argv[0]);
            return 1;
        }

        log_info("starting tun mode on interface %s\n", tunifname);
        
        tun_run(tunifname, rules);
    } else if (mode == MODE_INLINE) {
        if (!iif_set || !oif_set || !dmac_set) {
            help(argv[0]);
            return 1;
        }

        log_info("starting inline mode: in interface %s, out interface %s, target mac: %s\n", inifname, outifname, ether_ntoa((struct ether_addr *) dst_mac));

        inline_run(inifname, outifname, dst_mac, rules);
    } else {
        help(argv[0]);
    }

    return 1;
}