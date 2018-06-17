Sniff packets received over Ethernet. Sniffles is capable of parsing Ethernet, ARP, IP, TCP, and UDP packets.
Sniffles currently only supports Linux.

Sniffles is implemented in Python 3 and uses the hexdump and construct libraries. To use sniffles, both libraries must be installed:

```bash
pip3 install construct hexdump
```

Make sure your versions of construct and hexdump are updated.

Sniffles has 3 modes, `hexdump`, `pcap`, and `plaintext`. Hexdump will format and print sniffed bytes to stdout. Pcap will write parseable packets to a file in pcapng format, which is parseable by Wireshark. Plaintext will print a human-readable version of sniffed packets.

To use sniffles, you will need to provide an interface to sniff over. Valid interfaces can be found by running `ip addr show`. Common interfaces include `lo` and `eth0`.
