#include "tun.h"
#include "trace.h"
#include "log.h"
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t nhops;
    hop_t *hops;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <path-definition-file> <tun-interface-name>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "path definition file format:\n");
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

        return 1;
    }

    if (load_config(argv[1], &hops, &nhops) < 0) {
        return 1;
    }

    int fd = tun_alloc(argv[2]);

    if (fd < 0) {
        return 1;
    }

    uint8_t rbuf[0xffff];
    uint8_t wbuf[0xffff];

    while (1) {
        ssize_t len = read(fd, rbuf, 0xffff);

        if (len == 0) {
            continue;
        }

        if (len < 0) {
            log_error("error reading from tun device: %s\n", strerror(errno));
        }

        len = build_reply(hops, nhops, rbuf, (size_t) len, wbuf, 0xffff);

        if (len <= 0) {
            continue;
        }

        len = write(fd, wbuf, (size_t) len);

        if (len < 0) {
            log_error("error writing to tun: %s\n", strerror(errno));
        }
    }

    close(fd);

    return 0;
}