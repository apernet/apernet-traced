#ifndef APERNET_TRACED_INLINE_H
#define APERNET_TRACED_INLINE_H
#include "trace.h"

/**
 * @brief start traced in inline mode. (sniff & spoof)
 * 
 * @param in_ifname interface to monitor low-ttl packet on.
 * @param out_ifname interface to send out icmp msgs.
 * @param ether_src src mac for outgoing packets.
 * @param ether_dst dst mac for outgoint packets.
 * @param hops hop defs.
 * @param nhops number of hops.
 * 
 * @return int -1 on error, or never return.
 */
int inline_run(const char *in_ifname, const char *out_ifname,
    const uint8_t *ether_src, const uint8_t *ether_dst,
    const hop_t *hops, size_t nhops);

#endif // APERNET_TRACED_INLINE_H