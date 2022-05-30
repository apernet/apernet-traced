#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include "trace.h"
#include "log.h"

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
        if ((ptr - buffer) + sizeof(s->value) > bufsz) {
            return -EBUFOSZ;
        }

        memcpy(ptr, &(s->value), sizeof(s->value));
        ptr += sizeof(s->value);

        s = s->next;
        ++lse_count;
    }

    objhdr->length = sizeof(icmp_ext_obj_hdr_t) + lse_count * sizeof(uint32_t);

    return (ptr - buffer);
}

ssize_t build_reply(const hop_t *hops, size_t nhops, const uint8_t* inpkt, size_t insz, uint8_t *outpkt, size_t outsz) {
    uint8_t *optr = outpkt;
    const uint8_t *iptr = inpkt;

    const iphdr_t *ihdr = (iphdr_t *) iptr;
    
    if (insz < sizeof(iphdr_t)) {
        return -EBUFISZ;
    }

    if ((size_t) (ihdr->ttl - 1) > nhops) {
        return 0;
    }

    const hop_t *hop = &(hops[ihdr->ttl - 1]);

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

    if ((size_t) ((optr - outpkt) + 4 * ORIG_PAYLOAD_SZ) > outsz) {
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

int load_config(const char *config_file, hop_t **hops, size_t *nhops) {
    size_t ln = 0;
    int ret = 0;

    FILE *file = fopen(config_file, "r");

    if (file == NULL) {
        log_fatal("failed opening '%s': %s\n", config_file, strerror(errno));
        return -errno - 100;
    }

    char *addr = (char *) malloc(INET_ADDRSTRLEN);
    char *stacksdef = (char *) malloc(2048);
    
    hop_t *_hops = calloc(255, sizeof(hop_t));
    size_t _nhops = 0;

    *hops = _hops;
    
    while (fscanf(file, "%16s %2048s\n", addr, stacksdef) == 2) {
        log_debug("input hop %zu: %s, input stack: %s\n", ln, addr, stacksdef);
        
        ++ln;
        stack_t *prev = NULL, *head = NULL;

        uint32_t label;
        uint8_t exp;
        uint8_t s;
        uint8_t ttl;

        char *saveptr = NULL, *stackdef = NULL;

        for (stackdef = strtok_r(stacksdef, ",", &saveptr); ; stackdef = strtok_r(NULL, ",", &saveptr)) {
            if (stackdef == NULL) {
                if (head == NULL) {
                    ret = -EPARSE;
                    goto end;
                }

                break;
            }

            sscanf(stackdef, "%u:%hhu:%hhu:%hhu", &label, &exp, &s, &ttl);

            stack_t *stack = (stack_t *) malloc(sizeof(stack_t));
            stack->value = htonl(label) | exp << 9 | s << 8 | ttl;
            stack->next = NULL;

            if (head == NULL) {
                head = stack;
            }

            if (prev != NULL) {
                prev->next = stack;
            }

            log_debug("adding stack: l: %u, exp: %hhu, s: %hhu, ttl: %hhu; compuate val: %u\n", label, exp, s, ttl, stack->value);

            prev = stack;
        }

        _hops[_nhops].address = inet_addr(addr);
        _hops[_nhops].stack = head;
        ++_nhops;
    }

    *nhops = _nhops;

end:
    free(addr);
    free(stacksdef);
    fclose(file);
    return ret;
}