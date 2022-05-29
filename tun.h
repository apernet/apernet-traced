#ifndef APERNET_TAP_H
#define APERNET_TAP_H
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * @brief allocate a tun device.
 * 
 * @param dev ptr to a char array with size IFNAMSIZ. ifname will be stored in
 * this after device allocated.
 * @return int fd for the device (postive), or error (negative).
 */
int tun_alloc(char *dev);

#endif // APERNET_TAP_H