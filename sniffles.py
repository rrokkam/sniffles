import argparse
import hexdump
import pcap
import parse
import utils

_snaplen = 65600  # Bigger than max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = utils.raw_socket(interface)

    def sniff(self, mode='filter', time=0, **kwargs):
        modes = {
            'hexdump': hexdump.hexdump,
            'outfile': pcap.print_packet,
            'filter': _print_plaintext,
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
        except (TimeoutError, KeyboardInterrupt):
            if mode == 'outfile':  # need to close it
                kwargs['outfile'].close()

    def _print_plaintext(self, data, protocols):
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff 
                        packets received over Ethernet. Use on a Linux 
                        machine with construct version at least 2.9.39.''')

    parser.add_argument('interface', metavar='INTERFACE',
                        help='Interface to listen for traffic on.')
    parser.add_argument('-t', '--timeout', type=int, default=0,
                        help='''Time to capture for (in seconds). If set to 0 or
                        unspecified, ^C must be sent to close the program.''')

    format_parser = parser.add_mutually_exclusive_group()
    format_parser.add_argument('-x', '--hexdump', action='store_true',
                                help='Write hexdump to stdout.')
    format_parser.add_argument('-o', '--outfile', metavar='OUTFILE',
                                help='Write pcapng to a file.')
    format_parser.add_argument('-f', '--filter', nargs='+', 
                               choices=list(parse.HEADERS),
                               default=list(parse.HEADERS),
                               help='''Write human-readable output for the 
                               specified protocol(s) to stdout.''')

    kwargs = vars(parser.parse_args())
    sniffer = Sniffer(kwargs.pop('interface'))
    timeout = kwargs.pop('timeout')
    
    # TODO: find a cleaner way of determining which of the mutually exclusive args was passed.
    if kwargs.pop('hexdump'):
        sniffer.sniff('hexdump', timeout, **kwargs)
    elif kwargs['outfile'] is None:  # filter
        sniffer.sniff('filter', timeout, **kwargs)
    else:
        sniffer.sniff('outfile', timeout, **kwargs)        
