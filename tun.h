#ifndef APERNET_TAP_H
#define APERNET_TAP_H
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * @brief allocate a tun device.
 * 
 * @param dev name of tun device to create.
 * @return int fd for the device (postive), or error (negative).
 */
int tun_alloc(const char *dev);

#endif // APERNET_TAP_H