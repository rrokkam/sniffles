#!usr/bin/python3
import socket
import argparse
import hexdump
import pcap
import plaintext
from timeout import timeout

_snaplen = 65600  # Just over max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.socket.bind((interface, 0))

    def sniff(self, time=0, pcapfile=None, protocols=plaintext.HEADERS, dump=False):
        if file is not None:
            file = open(file, 'wb')
            pcap.write_header(file, _snaplen)
            print_mode = pcap.write_packet
        elif not dump:  # prefer using plaintext to hexdump
            print_mode = plaintext.print_plaintext
        else:
            print_mode = lambda packet, *_: hexdump.hexdump(packet)

        try:
            with timeout(time):
                while True:
                    packet, _ = self.socket.recvfrom(_snaplen)
                    print_mode(packet, file, protocols)
        except (TimeoutError, KeyboardInterrupt):
            if file is not None:
                file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff 
                        packets received over Ethernet. Use on a Linux 
                        machine with construct version at least 2.9.39.''')
    
    parser.add_argument('interface', metavar='INTERFACE',
                        help='Interface to listen for traffic on.')
    parser.add_argument('-t', '--timeout', type=int, default=0,
                        help='''Time to capture for (in seconds). If set to 0 or
                        unspecified, ^C must be sent to close the program.''')

    format_parser = parser.add_mutually_exclusive_group()
    format_parser.add_argument('-f', '--pcapfile', metavar='PCAPFILE',
                        help='Takes an arguments for the file name to output Pcap to.')
    format_parser.add_argument('-p', '--plaintext', nargs='*',
                        default=list(plaintext.HEADERS), choices=list(plaintext.HEADERS), 
                        help='''Print plaintext, with optional filtering for types 
                            of packets.''')
    format_parser.add_argument('-x', '--hexdump', action='store_true',
                        help='Print hexdump to stdout. Overrides -f and -o.')

    args = parser.parse_args()

    sniffer = Sniffer(args.interface)
    sniffer.sniff(args.timeout, args.pcapfile,
                  args.plaintext, args.hexdump)
