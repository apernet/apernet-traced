apernet-traced
---

a simple utility to fake IPv4 traceroute path, optionally with MPLS labels.

```
usage: ./traced -T -p PATHDEF_FILE -t TUN_IFNAME
usage: ./traced -I -p PATHDEF_FILE -i IN_IFNAME -o OUT_IFNAME -d DST_MAC

modes:
 -T: tun mode - traffic needs to be routed into the tun interface.
 -I: inline mode - sniff low-ttl traffic from IN_IFNAME, and sends reply to
     DST_MAC on OUT_IFNAME.
```

see `path.conf.example` for an example of `PATHDEF_FILE`.

### usage: tap mode

to use tap mode (assuming you want to tun interface to be named `tun0`):

```
$ sudo ./traced -Tp path.conf -i tun0
```

then, bring the `tun0` interface up, route some network(s) to it, then do a trace:

```
$ sudo ip link set tun0 up
$ sudo ip route add x.x.x.x/32 dev tun0
$ traceroute -e x.x.x.x
```

### usage: inline mode

inline mode sniff packets from given interface with `AF_PACKET`, then send out ICMP messages for low TTL packets to given dst mac on given interface.

to use inline mode (assuming sniffing from `eth0` and replying to `00:00:00:00:00:01` on `eth1`):

```
$ sudo ./traced -Ip path.conf -i eth0 -o eth1 -d 00:00:00:00:00:01
```

in most of the cases, the mac `00:00:00:00:00:01` should be the mac of router (so the ICMP messages are forwarded back to the sender). note that input and output interface can be the same interface.

to test this, either configure port mirror to send traffic to the box, or setup some sort of rules to route low-TTL packets to the box.

### compilation

just `git clone`, install `bison` and `flex`, then run `make` in the repo root.