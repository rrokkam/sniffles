import socket
import hexdump
import pcap
import parse
from timeout import timeout

_snaplen = 65600  # Just over max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.socket.bind((interface, 0))

    def sniff(self, time=0, file=None, protocols=parse.HEADERS, dump=False):
        if file is not None:
            file = open(file, 'wb')
            pcap.print_header(file, _snaplen)
            print_mode = pcap.print_packet
        elif not dump:  # prefer using plaintext to hexdump
            print_mode = parse.print_plaintext
        else:
            print_mode = lambda packet, *_: hexdump.hexdump(packet)

        try:
            with timeout(time):
                while True:
                    packet, _ = self.socket.recvfrom(_snaplen)
                    print_mode(packet, file, protocols)
        except TimeoutError:
            if file is not None:
                file.close()
