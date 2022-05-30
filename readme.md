apernet-traced
---

a simple utility to fake IPv4 traceroute path with MPLS labels. to use this utility, first, create the path definitions. path definitions file has the following format:

```
PATH_DEF    := HOP_DEF ['\n' PATH_DEF] ['\n']
HOP_DEF     := ipv4-address ' ' STACK_DEF
STACK_DEF   := LABEL_DEF [',' STACK_DEF]
LABEL_DEF   := label-value ':' exp-value ':' s-value ':' ttl-value
```

## usage

for example, if one uses this path definition:

```
192.0.2.1 114:0:0:11,514:0:0:51,1919:0:0:191,810:0:1:81
192.0.2.2 114:0:0:11,514:0:0:51,1919:0:0:191,810:0:1:81
```

the traceroute output will be:

```
traceroute to x.x.x.x (xxxx), 30 hops max, 60 byte packets
 1  192.0.2.1 (192.0.2.1) <MPLS:L=114,E=0,S=0,T=11/L=514,E=0,S=0,T=51/L=1919,E=0,S=0,T=191/L=810,E=0,S=1,T=81>  0.096 ms  0.079 ms  0.072 ms
 2  192.0.2.2 (192.0.2.2) <MPLS:L=114,E=0,S=0,T=11/L=514,E=0,S=0,T=51/L=1919,E=0,S=0,T=191/L=810,E=0,S=1,T=81>  0.061 ms  0.056 ms  0.050 ms
 3  * * *
 4  * * *
 5  * * *
 6  * * *
 7  * * *
<snip>
```

once you have a path definition, you can start `traced` in either tun mode or inline mode to start faking traceroute path.

### tap mode

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

### inline mode

inline mode sniff packets from given interface with `AF_PACKET`, then send out ICMP messages for low TTL packets to given dst mac on given interface.

to use inline mode (assuming sniffing from `eth0` and replying to `00:00:00:00:00:01` on `eth1`):

```
$ sudo ./traced -Ip path.conf -i eth0 -o eth1 -d 00:00:00:00:00:01
```

in most of the cases, the mac `00:00:00:00:00:01` should be the mac of router (so the ICMP messages are forwarded back to the sender). note that input and output interface can be the same interface.

to test this, either configure port mirror to send traffic to the box, or setup some sort of rules to route low-TTL packets to the box.

### compilation

just `git clone` and run `make` in the repo root.