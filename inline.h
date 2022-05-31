#ifndef APERNET_TRACED_INLINE_H
#define APERNET_TRACED_INLINE_H
#include "trace.h"

/**
 * @brief start traced in inline mode. (sniff & spoof)
 * 
 * @param in_ifname interface to monitor low-ttl packet on.
 * @param out_ifname interface to send out icmp msgs.
 * @param ether_dst dst mac for outgoint packets.
 * @param rules reply rules.
 * 
 * @return int -1 on error, or never return.
 */
int inline_run(const char *in_ifname, const char *out_ifname,
    const uint8_t *ether_dst, const rule_t *rules);

/**
 * @brief get interface index by name.
 * 
 * @param ifname name of interface.
 * @return int interface index, or negative value on error.
 */
int ifname2index(const char *ifname);

/**
 * @brief get ethernet address by interface index.
 * 
 * @param ifindex ifindex of interface.
 * @param addr buffer to store address.
 * @return int 0 on success, or negative value on error.
 */
int get_eth_addr(int ifindex, uint8_t *addr);

#endif // APERNET_TRACED_INLINE_H