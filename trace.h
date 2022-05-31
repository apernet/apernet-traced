#ifndef APERNET_TRACED_H
#define APERNET_TRACED_H
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
#define EPAYLOADSZ 4
#define ENUMHOPS 5

#define ICMP_EXTYPE_MPLS_LSTACK 1
#define MPLS_LSTACK_CTYPE_INCOMING_STACK 1

#define HOP_TTPE_LITERAL 0
#define HOP_TYPE_SRC 1
#define HOP_TYPE_DST 2
#define HOP_TYPE_RANDOM 3

#define VAL_TYPE_LITERAL 0
#define VAL_TYPE_RANDOM 1

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
    uint32_t value; // to be removed

    int label_type;
    uint32_t label; // if label_type == VAL_TYPE_LITERAL
    uint32_t label_rand_min; // if label_type == VAL_TYPE_RANDOM
    uint32_t label_rand_max; // if label_type == VAL_TYPE_RANDOM

    int exp_type;
    uint8_t exp; // if exp_type == VAL_TYPE_LITERAL
    uint8_t exp_rand_min; // if exp_type == VAL_TYPE_RANDOM
    uint8_t exp_rand_max; // if exp_type == VAL_TYPE_RANDOM

    int s_type;
    uint8_t s; // if s_type == VAL_TYPE_LITERAL
    uint8_t s_rand_min; // if s_type == VAL_TYPE_RANDOM
    uint8_t s_rand_max; // if s_type == VAL_TYPE_RANDOM

    int ttl_type;
    uint8_t ttl; // if ttl_type == VAL_TYPE_LITERAL
    uint8_t ttl_rand_min; // if ttl_type == VAL_TYPE_RANDOM
    uint8_t ttl_rand_max; // if ttl_type == VAL_TYPE_RANDOM

    struct __stack *next;
} stack_t;

typedef struct __hop {
    int type; // HOP_TYPE_*

    uint32_t address; // if type == HOP_TYPE_LITERAL
    uint32_t address_rand_min; // if type == HOP_TYPE_RANDOM
    uint32_t address_rand_max; // if type == HOP_TYPE_RANDOM

    stack_t *stack;
} hop_t;

typedef struct __rule {
    uint32_t from;
    uint32_t from_mask;
    uint32_t to;
    uint32_t to_mask;
    hop_t *hops;
    size_t nhops;

    struct __rule *next;
} rule_t;

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

#endif // APERNET_TRACED_H