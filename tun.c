#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "tun.h"
#include "log.h"

int tun_alloc(const char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        log_fatal("failed to open tun device: %s\n", strerror(errno));
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0){
        log_fatal("failed to TUNSETIFF: %s\n", strerror(errno));
        close(fd);
        return err;
    }

    log_debug("tun device allocated on fd %d: '%s'\n", fd, ifr.ifr_name);

    return fd;
}

int tun_run(const char *dev, const hop_t *hops, size_t nhops) {
    int fd = tun_alloc(dev);

    if (fd < 0) {
        return -1;
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
            break;
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

    // should be unreached

    close(fd);

    return -1;
}