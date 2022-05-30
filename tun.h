#ifndef APERNET_TRACED_TUN_H
#define APERNET_TRACED_TUN_H
#include "trace.h"
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * @brief allocate a tun device.
 * 
 * @param dev name of tun device to create.
 * @return int fd for the device (postive), or error (negative).
 */
int tun_alloc(const char *dev);

/**
 * @brief start traced in tun mode.
 * 
 * @param dev name of tun device.
 * @param hops hop defs.
 * @param nhops number of hops.
 * 
 * @return -1 on error, or never return.
 */
int tun_run(const char *dev, const hop_t *hops, size_t nhops);

#endif // APERNET_TRACED_TUN_H