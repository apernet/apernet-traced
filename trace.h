#ifndef APERNET_TRACE_H
#define APERNET_TRACE_H
#include <stdint.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// number of 32-bit words to take from orig packet.
#define ORIG_PAYLOAD_SZ 32

// TTL for outgoing packets
#define OUTPKT_TTL 64

#define EBUFOSZ 1
#define EBUFISZ 2
#define EPARSE 3

#define ICMP_EXTYPE_MPLS_LSTACK 1
#define MPLS_LSTACK_CTYPE_INCOMING_STACK 1

typedef struct iphdr iphdr_t;
typedef struct __attribute__((__packed__)) __icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t unused_0;
    uint8_t length; // length of orig payload, in 32-bit words.
    uint16_t unused_1;
} icmphdr_t;

typedef struct __stack {
    uint32_t value;
    struct __stack *next;
} stack_t;

typedef struct hop {
    uint32_t address;
    stack_t *stack;
} hop_t;

typedef struct __attribute__((__packed__)) __icmp_ext_obj_hdr {
    uint16_t length;
    uint8_t class;
    uint8_t type;
} icmp_ext_obj_hdr_t;

/**
 * @brief build rfc4950 payload from stack definition
 * 
 * @param stack stack definition.
 * @param buffer buffer to write to.
 * @param bufsz size of the given buffer.
 * @return ssize_t bytes written (postive), or error code (negative).
 */
ssize_t build_rfc4950(const stack_t* stack, uint8_t *buffer, size_t bufsz);

/**
 * @brief construct icmp reply from incoming packet.
 * 
 * @param hops hops config.
 * @param nhops hops count.
 * @param inpkt incoming packet.
 * @param insz incoming packet size.
 * @param outpkt buffer for outgoing packet.
 * @param outsz buffer size.
 * @return ssize_t  bytes written (postive), zero (noting to reply), or error code (negative).
 */
ssize_t build_reply(const hop_t *hops, size_t nhops, const uint8_t* inpkt, size_t insz, uint8_t *outpkt, size_t outsz);

/**
 * @brief destroy hop struct.
 * 
 * @param hop hops to destroy.
 */
void destroy_hop(hop_t *hop[]);

/**
 * @brief load hop configuration from file.
 * 
 * @param config_file path to the config file to load hops from.
 * @param hops ptr to array of hop; hops. destroy with destroy_hop() when done working with it.
 * @param nhops ptr to size_t; will store number of hops defined.
 * @return int zero on success, negative on error.
 */
int load_config(const char *config_file, hop_t **hops, size_t *nhops);

/**
 * @brief compute inet checksum.
 * 
 * @param data data.
 * @param length data length.
 * @return uint16_t 16-bit checksum.
 */
uint16_t cksum(uint8_t* data, size_t length);

#endif // APERNET_TRACE_H