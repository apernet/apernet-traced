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