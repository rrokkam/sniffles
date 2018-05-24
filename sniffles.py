import hexdump
import pcap
import parse
from timeout import timeout

_snaplen = 65600  # Bigger than max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.socket.bind((interface, 0))

    def sniff(self, mode='filter', time=0, **kwargs):
        modes = {
            'hexdump': hexdump.hexdump,
            'outfile': pcap.print_packet,
            'filter': parse.print_plaintext,
        }

        if mode == 'outfile':
            kwargs['outfile'] = open(kwargs['outfile'], 'wb')
            pcap.print_header(kwargs['outfile'], _snaplen)

        try:
            with timeout(time):  # raise exception after time seconds
                while True:
                    data, _ = self.socket.recvfrom(_snaplen)
                    modes[mode](data, kwargs)
        except (TimeoutError, KeyboardInterrupt):
            if mode == 'outfile':
                kwargs['outfile'].close()
