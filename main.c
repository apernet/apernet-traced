#include "tun.h"
#include "trace.h"
#include "log.h"

int main(int argc, char **argv) {
    size_t nhops;
    hop_t *hops;

    load_config("path.conf", &hops, &nhops);

    int fd = tun_alloc("tun1");

    if (fd < 0) {
        return 1;
    }

    close(fd);

    uint8_t buffer[0xffff];

    while (1) {
        ssize_t len = read(fd, buffer, 0xffff);
        if (len > 0) {
            log_debug("%zu bytes from tun.\n", len);
        }
    }     

    return 0;
}