#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include "trace.h"
#include "log.h"

uint16_t cksum(uint8_t* data, size_t length) {
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    if (length & 0x01) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    return htons(~acc);
}

uint32_t rand_range(uint32_t min, uint32_t max) {
    if (min >= max) {
        return min;
    }

    uint32_t range = max - min;

    uint32_t val = rand() & 0xff;
    val |= (rand() & 0xff) << 8;
    val |= (rand() & 0xff) << 16;
    val |= (rand() & 0xff) << 24;

    return min + (val % range);
}

ssize_t build_rfc4950(const stack_t* stack, uint8_t *buffer, size_t bufsz) {
    if (stack == NULL) {
        return 0;
    }

    uint8_t *ptr = buffer;

    uint32_t *exthdr = (uint32_t *) ptr;

    if (sizeof(uint32_t) > bufsz) {
        return -EBUFOSZ;
    }

    *exthdr = htonl(2 << 28);
    
    ptr += sizeof(uint32_t);

    icmp_ext_obj_hdr_t *objhdr = (icmp_ext_obj_hdr_t *) ptr;

    if ((ptr - buffer) + sizeof(icmp_ext_obj_hdr_t) > bufsz) {
        return -EBUFOSZ;
    }

    objhdr->class = ICMP_EXTYPE_MPLS_LSTACK;    
    objhdr->type = MPLS_LSTACK_CTYPE_INCOMING_STACK;

    ptr += sizeof(icmp_ext_obj_hdr_t);

    size_t lse_count = 0;
    const stack_t *l = stack;

    uint32_t label;
    uint8_t exp;
    uint8_t s;
    uint8_t ttl;

    while (l != NULL) {
        label = l->label;
        exp = l->exp;
        s = l->s;
        ttl = l->ttl;

        if (l->label_type == VAL_TYPE_RANDOM) {
            label = rand_range(l->label_rand_min, l->label_rand_max);
        }

        if (l->s_type == VAL_TYPE_RANDOM) {
            s = rand_range(l->s_rand_min, l->s_rand_max);
        }

        if (l->exp_type == VAL_TYPE_RANDOM) {
            exp = rand_range(l->exp_rand_min, l->exp_rand_max);
        }

        if (l->ttl_type == VAL_TYPE_RANDOM) {
            ttl = rand_range(l->ttl_rand_min, l->ttl_rand_max);
        }

        if ((ptr - buffer) + sizeof(uint32_t) > bufsz) {
            return -EBUFOSZ;
        }

        uint32_t value = htonl(label << 12 | exp << 9 | s << 8 | ttl);

        memcpy(ptr, &(value), sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        l = l->next;
        ++lse_count;
    }

    objhdr->length = htons(sizeof(icmp_ext_obj_hdr_t) + lse_count * sizeof(uint32_t));

    return (ptr - buffer);
}

const rule_t *match(const rule_t *rules, uint32_t src, uint32_t dst) {
    const rule_t *rule = rules;

    while (rule != NULL) {
        uint32_t from_mask = htonl(rule->from_mask);
        uint32_t to_mask = htonl(rule->to_mask);

        if ((rule->from & from_mask) == (src & from_mask) &&
            (rule->to & to_mask) == (dst & to_mask)) {
            return rule;
        }

        rule = rule->next;
    }

    return NULL;
}

ssize_t build_reply(const rule_t *rules, const uint8_t* inpkt, size_t insz, uint8_t *outpkt, size_t outsz) {
    uint8_t *optr = outpkt;
    const uint8_t *iptr = inpkt;

    const iphdr_t *ihdr = (iphdr_t *) iptr;
    
    if (insz < sizeof(iphdr_t)) {
        return -EBUFISZ;
    }

    const rule_t *rule = match(rules, ihdr->saddr, ihdr->daddr);

    if (rule == NULL) {
        return 0;
    }

    if ((size_t) (ihdr->ttl - 1) > rule->nhops) {
        return 0;
    }

    const hop_t *hop = &(rule->hops[ihdr->ttl - 1]);

    iphdr_t *ohdr = (iphdr_t *) optr;
    
    if (sizeof(iphdr_t) > outsz) {
        return -EBUFOSZ;
    }

    memset(optr, 0, sizeof(iphdr_t));

    ohdr->daddr = ihdr->saddr;
    ohdr->saddr = hop->address;
    ohdr->ttl = OUTPKT_TTL - ihdr->ttl;
    ohdr->protocol = IPPROTO_ICMP;
    ohdr->ihl = 5;
    ohdr->version = 4;

    if (hop->type == HOP_TYPE_RANDOM) {
        ohdr->saddr = htonl(rand_range(ntohl(hop->address_rand_min), ntohl(hop->address_rand_max)));
    } else if (hop->type == HOP_TYPE_SRC) {
        ohdr->saddr = ihdr->saddr;
    } else if (hop->type == HOP_TYPE_DST) {
        ohdr->saddr = ihdr->daddr;
    }

    optr += sizeof(iphdr_t);

    icmphdr_t *oicmphdr = (icmphdr_t *) optr;

    if ((optr - outpkt) + sizeof(icmphdr_t) > outsz) {
        return -EBUFOSZ;
    }

    memset(optr, 0, sizeof(icmphdr_t));

    oicmphdr->type = ICMP_TIME_EXCEEDED;
    oicmphdr->code = ICMP_EXC_TTL;
    oicmphdr->length = ORIG_PAYLOAD_SZ;

    optr += sizeof(icmphdr_t);

    if ((size_t) ((optr - outpkt) + 4 * ORIG_PAYLOAD_SZ) > outsz) {
        return -EBUFOSZ;
    }

    size_t copy_sz = 4 * ORIG_PAYLOAD_SZ;
    if (copy_sz > insz) {
        copy_sz = insz;
    }

    memcpy(optr, inpkt, copy_sz);

    if (copy_sz < 4 * ORIG_PAYLOAD_SZ) {
        memset(optr + copy_sz, 0, 4 * ORIG_PAYLOAD_SZ - copy_sz);
    }

    optr += 4 * ORIG_PAYLOAD_SZ;

    ssize_t rfc4950_len = build_rfc4950(hop->stack, optr, outsz - (optr - outpkt));

    if (rfc4950_len < 0) {
        return rfc4950_len;
    }

    optr += rfc4950_len;

    oicmphdr->checksum = cksum(((uint8_t *) oicmphdr), optr - (uint8_t *) oicmphdr);

    size_t tot_len = (optr - outpkt);

    if (tot_len > 0xffff) {
        return -EPAYLOADSZ;
    }

    ohdr->tot_len = htons(tot_len);
    ohdr->check = cksum(outpkt, tot_len);

    return tot_len;
}