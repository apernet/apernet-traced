#ifndef APERNET_TRACED_TUN_H
#define APERNET_TRACED_TUN_H
#include "trace.h"
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * @brief start traced in tun mode.
 * 
 * @param dev name of tun device.
 * @param rules reply rules.
 * 
 * @return int -1 on error, or never return.
 */
int tun_run(const char *dev, const rule_t *rules);

#endif // APERNET_TRACED_TUN_H