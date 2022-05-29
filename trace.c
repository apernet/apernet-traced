#include <string.h>
#include "trace.h"

ssize_t build_rfc4950(const stack_t* stack, uint8_t *buffer, size_t bufsz) {
    uint8_t *ptr = buffer;

    icmp_ext_hdr_t *exthdr = (icmp_ext_hdr_t *) ptr;

    if (sizeof(icmp_ext_hdr_t) > bufsz) {
        return -EBUFOSZ;
    }

    exthdr->ver = 2;
    exthdr->reserved = 0;
    exthdr->cksum = 0;
    
    ptr += sizeof(icmp_ext_hdr_t);

    icmp_ext_obj_hdr_t *objhdr = (icmp_ext_obj_hdr_t *) ptr;

    if ((ptr - buffer) + sizeof(icmp_ext_obj_hdr_t) > bufsz) {
        return -EBUFOSZ;
    }

    objhdr->class = ICMP_EXTYPE_MPLS_LSTACK;    
    objhdr->type = MPLS_LSTACK_CTYPE_INCOMING_STACK;

    ptr += sizeof(icmp_ext_obj_hdr_t);

    size_t lse_count = 0;
    const stack_t *s = stack;

    while (s != NULL) {
        if ((ptr - buffer) + sizeof(label_t) > bufsz) {
            return -EBUFOSZ;
        }

        memcpy(ptr, s->label, sizeof(label_t));
        ptr += sizeof(label_t);

        s = s->next;
    }

    return (ptr - buffer);
}

ssize_t build_reply(const hop_t *hops[], size_t nhops, const uint8_t* inpkt, size_t insz, uint8_t *outpkt, size_t outsz) {
    uint8_t *optr = outpkt;
    const uint8_t *iptr = inpkt;

    const iphdr_t *ihdr = (iphdr_t *) iptr;
    
    if (insz < sizeof(iphdr_t)) {
        return -EBUFISZ;
    }

    if (ihdr->ttl - 1 > nhops) {
        return 0;
    }

    const hop_t *hop = hops[ihdr->ttl - 1];

    iphdr_t *ohdr = (iphdr_t *) optr;
    
    if (sizeof(iphdr_t) > outsz) {
        return -EBUFOSZ;
    }

    memset(optr, 0, sizeof(iphdr_t));

    ohdr->daddr = ihdr->saddr;
    ohdr->saddr = hop->address;
    ohdr->ttl = OUTPKT_TTL;
    ohdr->protocol = IPPROTO_ICMP;
    ohdr->ihl = 5;
    ohdr->version = 4;

    optr += sizeof(iphdr_t);

    icmphdr_t *oicmphdr = (icmphdr_t *) optr;

    if ((optr - outpkt) + sizeof(icmphdr_t) > outsz) {
        return -EBUFOSZ;
    }

    memset(optr, 0, sizeof(icmphdr_t));

    oicmphdr->code = ICMP_TIME_EXCEEDED;
    oicmphdr->type = ICMP_EXC_TTL;
    oicmphdr->length = ORIG_PAYLOAD_SZ;

    optr += sizeof(icmphdr_t);

    if ((optr - outpkt) + 4 * ORIG_PAYLOAD_SZ > outsz) {
        return -EBUFOSZ;
    }

    memcpy(optr, inpkt, 4 * ORIG_PAYLOAD_SZ);

    optr += 4 * ORIG_PAYLOAD_SZ;

    ssize_t rfc4950_len = build_rfc4950(hop->stack, optr, outsz - (optr - outpkt));

    if (rfc4950_len < 0) {
        return rfc4950_len;
    }

    optr += rfc4950_len;

    return (optr - outpkt);
}