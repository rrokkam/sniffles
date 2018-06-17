from construct import *


class MACAddressAdapter(Adapter):
    def _decode(self, obj, *_):
        return ':'.join(['{:02x}'.format(o) for o in obj])

    def _encode(self, obj, *_):
        return [int(o, 16) for o in obj.split(':')]


class IPAddressAdapter(Adapter):
    def _decode(self, obj, *_):
        return '.'.join([str(o) for o in obj])

    def _encode(self, obj, *_):
        return [int(o) for o in obj.split('.')]


HEADERS = {
    'Ethernet': Struct(
        'dest_mac' / MACAddressAdapter(Bytes(6)),
        'src_mac' / MACAddressAdapter(Bytes(6)),
        'ethernet_type' / BytesInteger(2),
        '_headerlen' / Computed(14)
    ),

    'ARP': Struct(
        '_start' / Tell,
        'hardware_type' / BytesInteger(2),
        'protocol_type' / BytesInteger(2),
        'hardware_addr_len' / BytesInteger(1),
        'protocol_addr_len' / BytesInteger(1),
        'opcode' / BytesInteger(2),
        'sender_hw_addr' / MACAddressAdapter(Bytes(this.hardware_addr_len)),
        'sender_proto_addr' / IPAddressAdapter(Bytes(this.protocol_addr_len)),
        'target_hw_addr' / MACAddressAdapter(Bytes(this.hardware_addr_len)),
        'target_proto_addr' / IPAddressAdapter(Bytes(this.protocol_addr_len)),
        '_end' / Tell,
        '_headerlen' / Computed(this._end - this._start)
    ),

    'IP': BitStruct(
        'version' / BitsInteger(4),
        'IHL' / BitsInteger(4),
        'DSCP' / BitsInteger(6),
        'ECN' / BitsInteger(2),
        'length' / Bytewise(BytesInteger(2)),
        'identification' / Bytewise(BytesInteger(2)),
        'flags' / BitsInteger(3),
        'offset' / BitsInteger(13),
        'TTL' / Bytewise(BytesInteger(1)),
        'protocol' / Bytewise(BytesInteger(1)),
        'checksum' / Bytewise(BytesInteger(2)),
        'src_ip_addr' / Bytewise(IPAddressAdapter(Bytes(4))),
        'dst_ip_addr' / Bytewise(IPAddressAdapter(Bytes(4))),
        'options' / If(this.IHL > 5, Bytewise(Bytes(this.IHL * 4 - 20))),
        '_headerlen' / Computed(this.IHL * 4)
    ),

    'TCP': BitStruct(
        'src_port' / Bytewise(BytesInteger(2)),
        'dest_port' / Bytewise(BytesInteger(2)),
        'seq_num' / Bytewise(BytesInteger(4)),
        'ack_num' / Bytewise(BytesInteger(4)),
        'offset' / BitsInteger(4),
        'reserved' / Padding(3),
        'NS' / Flag,
        'CWR' / Flag,
        'ECE' / Flag,
        'URG' / Flag,
        'ACK' / Flag,
        'PSH' / Flag,
        'RST' / Flag,
        'SYN' / Flag,
        'FIN' / Flag,
        'options' / If(this.offset > 5, Bytewise(Bytes(this.offset * 4 - 20))),
        '_headerlen' / Computed(this.offset * 4)
    ),

    'UDP': Struct(
        'src_port' / BytesInteger(2),
        'dest_port' / BytesInteger(2),
        'length' / BytesInteger(2),
        'checksum' / BytesInteger(2),
        '_headerlen' / Computed(8)
    )
}

CONDITIONS = {
    'Ethernet': lambda packet: True,
    'ARP': lambda packet: packet['Ethernet'].ethernet_type == 2054,
    'IP': lambda packet: packet['Ethernet'].ethernet_type == 2048,
    'TCP': lambda packet: 'IP' in packet and packet['IP'].protocol == 6,
    'UDP': lambda packet: 'IP' in packet and packet['IP'].protocol == 17,
}


def print_plaintext(packet, _, protocols):
    parsed = {}
    offset = 0
    try:
        for head in HEADERS:
            if CONDITIONS[head](parsed):
                parsed[head] = HEADERS[head].parse(packet[offset:])
                offset += parsed[head]._headerlen
    except StreamError:
        return  # ignore garbled packet

    print('\n'.join([header(head, parsed[head]) for head in parsed
                     if head in protocols]), end='\n\n')


def header(head, body):
    pairs = ['{}={}'.format(k, v) for k, v in body.items()
             if not k.startswith('_')]
    return '{}({})'.format(head, ', '.join(pairs))
