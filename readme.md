apernet-traced
---

a simple utility to fake IPv4 traceroute path with MPLS labels. to use this utility, first, create a path definition. path definition file has the following format:

```
PATH_DEF    := HOP_IP ' ' STACK_DEF '\n'
HOP_IP      := ipv4-address
STACK_DEF   := LABEL_DEF [',' STACK_DEF]
LABEL_DEF   := label-value ':' exp-value ':' s-value ':' ttl-value
```

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

once you have a path definition, let `traced` create a tun interface like this (say you want it to be `tun0`):

```
$ sudo ./traced path.conf tun0
```

then, bring the `tun0` interface up, route some network(s) to it, then do a trace:

```
$ sudo ip link set tun0 up
$ sudo ip route add x.x.x.x/32 dev tun0
$ traceroute -e x.x.x.x
```

### compilation

just `git clone` and run `make` in the repo root.