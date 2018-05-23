#!/usr/bin/env python3

import hexdump
import argparse
import socket
from datetime import datetime
import calendar

import pcap
import parse
import utils

_snaplen = 65600  # Bigger than max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.ntohs(0x0003))  # all packets
        self.socket.bind((interface, 0))

    def sniff(self, mode, time, **kwargs):
        modes = {
            'hexdump': hexdump.hexdump,
            'protocols': print_plaintext,
            'outfile': print_pcap
        }

        # need to print header of pcap if outfile
        if mode == 'outfile':
            kwargs['outfile'] = open(kwargs['outfile'], 'wb')
            pcap.print_header(kwargs['outfile'], _snaplen)

        try:
            with utils.timeout(time):  # raise exception after time seconds
                while True:
                    data, _ = self.socket.recvfrom(_snaplen)
                    modes[mode](data, kwargs)
        except TimeoutError:
            if mode == 'outfile':  # need to close it
                kwargs['outfile'].close()

    def print_pcap(self, data, file):
        time = calendar.timegm(datetime.now().timetuple()) * 10**6  # microseconds to seconds
        pcap.print_packet(data, file, time)

    def print_plaintext(self, data, protocols):
        packet = parse_packet(data)
        packet_string = self.packetString(packet, protocols)
        if len(packet_string) > 0:
            print(packet_string, end='\n\n')

    def _valString(self, key, value):
        if key[0] == '*':
            return ', '.join([self._valString(k, v) for k, v in value.items() if k[0] != '_'])
        else:
            return '{}={}'.format(key, value)

    def _headerString(self, header_name, header):
        pairs = [self._valString(k, v)
                 for k, v in header.items() if k[0] != '_']
        return header_name + '(' + ', '.join(pairs) + ')'

    def packetString(self, packet, protocols):
        heads = [self._headerString(h, packet[h]) for h in parse.HEADERS
                 if h in protocols and h[0] != '_' and h in packet]  # nonetype is not iterable
        return '\n'.join(heads)

if __name__ == "__main__":
    utils.register_atexit()

    parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff packets.
                        Use on a Linux machine with construct 2.9.39.''')
    parser.add_argument('interface', metavar='INTERFACE',
                        help='Interface to listen for traffic on.')
    parser.add_argument('-t', '--timeout', default=0, type=int,
                        help='''Time to capture for (in seconds). If set to 0 or
                        unspecified, ^C must be sent to close the program.''')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-o', '--outfile', metavar='OUTFILE',
                        help='Write wireshark-readable pcapng to a file.')
    group.add_argument('-x', '--hexdump', action='store_true',
                        help='Write hexdump to stdout.')
    group.add_argument('-f', '--filter', nargs='+', choices=list(parse.HEADERS), 
                        help='Write human-readable output for the specified protocol(s) to stdout.')

    args = vars(parser.parse_args())

    # need to figure out how to find easily which element of a mutually exclusive group was picked.

    sniffer = Sniffer(args.pop['interface'])
    time = args.pop['timeout']
    if 'outfile' in args:
        sniffer.sniff('outfile', time, args)
    elif 'hexdump' in args:
        sniffer.sniff('hexdump', time, args)
    elif 'filter' in args:
        sniffer.sniff('filter', time, args)
