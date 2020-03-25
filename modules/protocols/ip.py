import random

import bitstring
from netaddr import IPAddress

from modules.constants import IPFlag, IPProtocol
from modules.protocols.udp import UDP


class IPv4:

    def compute_checksum(self):
        s = 0
        msg = self.pack(full=False)
        if len(msg) % 2 == 1:
            msg += b"\x00"
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i + 1] << 8)
            t = s + w
            s = (t & 0xffff) + (t >> 16)
        s = ~s & 0xffff
        return ((s << 8) & 0xff00) | (s >> 8)

    def __init__(self, source, destination, ttl):
        self.parent = None
        self.encapsulated = None

        self.version = 4
        self.header_len = 5
        self.dscp = 0
        self.ecn = 0
        self.len = 0
        self.ident = random.randint(0, 0xffff)
        self.flags = IPFlag.DONT_FRAGMENT.value
        self.ttl = ttl
        self.protocol = IPProtocol.TCP.value
        self.checksum = 0x0000
        if isinstance(source, int):
            self.source = source
        elif isinstance(source, str):
            self.source = int(IPAddress(source))
        if isinstance(destination, int):
            self.destination = destination
        elif isinstance(destination, str):
            self.destination = int(IPAddress(destination))

    def pack(self, full=True):
        ret = bitstring.pack("""
            uintbe:8, uintbe:8, uintbe:16, uintbe:16, uintbe:16,
            uintbe:8, uintbe:8, uintbe:16, uintbe:32, uintbe:32""",
                             self.version << 4 | self.header_len, self.dscp << 6 | self.ecn, self.len, self.ident,
                             self.flags, self.ttl,
                             self.protocol, self.checksum, self.source, self.destination).tobytes()
        if full:
            if self.parent is not None:
                ret = self.parent.pack(full=True) + ret
        return ret

    def UDP(self, source_port, destination_port):
        self.encapsulated = UDP(source_port, destination_port)
        self.protocol = IPProtocol.UDP.value
        self.encapsulated.parent = self
        return self.encapsulated
