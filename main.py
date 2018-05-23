#!/usr/bin/env python3

import argparse
import sniffles
import parse

parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff packets.
                    Use on a Linux machine with construct 2.9.39.''')
parser.add_argument('interface', metavar='INTERFACE',
                    help='Interface to listen for traffic on.')
parser.add_argument('-t', '--timeout', default=0, type=int,
                    help='''Time to capture for (in seconds). If set to 0 or
                    unspecified, ^C must be sent to close the program.''')

out_format = parser.add_mutually_exclusive_group()
out_format.add_argument('-o', '--outfile', metavar='OUTFILE',
                    help='Write wireshark-readable pcapng to a file.')
out_format.add_argument('-x', '--hexdump', action='store_true',
                    help='Write hexdump to stdout.')
out_format.add_argument('-f', '--filter', nargs='+', choices=list(parse.HEADERS), 
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