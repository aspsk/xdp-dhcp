# A dummy DHCP server written in XDP

This is a draft of a DHCP server written in XDP. The usage is as follows:

```
VM
--------
| eth0 | --> tap [XDP]
--------
```

Here a VM sends a DHCP request, and an XDP program sitting on the tap device
responds with a config.

## Examples

```
xdp-dhcp veth0
        --attach-type <attach-type>
        --ipv4 192.168.0.17/24
        --lease <lease>

<attach-type> ::= xdp | xdpgeneric
<lease> ::= <time in some human-readable format>
```
