#!/usr/bin/env python3

import hexdump
import argparse
import socket
from datetime import datetime
import calendar

import pcap
from parse import HEADERS, parsePacket
import utils

MAX_PACKET_SIZE = 65600  # Bigger than max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.ntohs(0x0003))  # all packets
        self.socket.bind((interface, 0))

    def sniff(self, outfile=None, time=0, dump=False, protocols=HEADERS):
        file = None
        if dump:
            printFunc = self.printHex
        elif outfile is None:
            printFunc = self.printPlainText
        else:
            file = open(outfile, 'wb')
            pcap.printHeaders(file, MAX_PACKET_SIZE)
            printFunc = self.printPcap
        
        try:
            with utils.timeout(time):  # raise exception after time seconds
                while True:
                    data = self.socket.recvfrom(MAX_PACKET_SIZE)[0]
                    printFunc(data, file, protocols)  # might ignore args
        except TimeoutError:
            if outfile is not None:  # need to close it
                file.close()

    def close(self):
        self.socket.close()

    def printHex(self, data, *_):
        hexdump.hexdump(data)

    def printPcap(self, data, file, *_):
        time = calendar.timegm(datetime.now().timetuple()) * 10**6  # microseconds to seconds
        pcap.printEnhancedPacket(file, time, data)

    def printPlainText(self, data, file, protocols):
        packet = parsePacket(data)
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
        heads = [self._headerString(h, packet[h]) for h in HEADERS
                 if h in protocols and h[0] != '_' and h in packet]  # nonetype is not iterable
        return '\n'.join(heads)


if __name__ == "__main__":  # TODO : add atexit
    utils.register_atexit()

    parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff packets.
                        Use on a Linux machine. Works with construct 2.9.39.''')
    parser.add_argument('interface', metavar='INTERFACE', default='eth0',
                        help='Interface to listen for traffic on.')
    parser.add_argument('-t', '--timeout', default=0, type=int,
                        help='''Time to capture for (in seconds). If 
                        unspecified, ^C must be sent to close the program.''')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-o', '--outfile', metavar='OUTFILE',
                        help='Write Pcap to a file.')
    group.add_argument('-x', '--hexdump', action='store_true',
                        help='Write hexdump to stdout.')
    group.add_argument('-f', '--filter', nargs='+', default=list(HEADERS), choices=list(HEADERS), 
                        help='Write human-readable output for the specified protocol(s) to stdout.')

    args = vars(parser.parse_args())

    sniffer = Sniffer(args['interface'])
    sniffer.sniff(args['outfile'], args['timeout'],
                  args['hexdump'], args['filter'])
