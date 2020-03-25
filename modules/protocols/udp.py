import bitstring


class UDP:

    def pseudo_header(self):
        return bitstring.pack("uintbe:32,uintbe:32,uintbe:8,uintbe:8,uintbe:16",
                              self.parent.source, self.parent.destination, 0, self.parent.protocol,
                              len(self.data) + 8).tobytes()

    def compute_checksum(self):
        s = 0
        msg = self.pseudo_header() + self.pack(full=False)
        if len(msg) % 2 == 1:
            msg += b"\x00"
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i + 1] << 8)
            t = s + w
            s = (t & 0xffff) + (t >> 16)
        s = ~s & 0xffff
        return ((s << 8) & 0xff00) | (s >> 8)

    def __init__(self, source_port, destination_port):
        self.parent = None

        self.data = ""
        self.source_port = source_port
        self.destination_port = destination_port
        self.len = 0
        self.checksum = 0

    def pack(self, full=True):
        ret = bitstring.pack("""
            uintbe:16, uintbe:16, uintbe:16, uintbe:16""",
                             self.source_port, self.destination_port, self.len, self.checksum).tobytes() + self.data
        if full:
            if self.parent is not None:
                ret = self.parent.pack(full=True) + ret
        return ret

    def Payload(self, data):
        self.data = data
        self.len = 8 + len(data)
        self.parent.len = self.parent.header_len * 4 + self.len
        self.parent.checksum = self.parent.compute_checksum()
        self.checksum = self.compute_checksum()
        return self
