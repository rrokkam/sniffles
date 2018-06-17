import hexdump
import socket
import pcap
import parse
from timeout import timeout

_snaplen = 65600  # Bigger than max Ethernet + IP + TCP header size


class Sniffer:
    def __init__(self, interface):
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.socket.bind((interface, 0))

    def sniff(self, time=0, file=None, hex=False, protocols=parse.HEADERS):
        if file is not None:
            file = open(file, 'wb')
            pcap.printHeaders(file, _snaplen)
            print_mode = pcap.print_packet
        elif hexdump:
            print_mode = lambda packet, *_: hexdump.hexdump(packet)
        else:
            print_mode = parse.print_plaintext

        try:
            with timeout(time):
                while True:
                    packet, _ = self.socket.recvfrom(_snaplen)
                    print_mode(packet, file, protocols)
        except TimeoutError:
            if file is not None:
                file.close()
