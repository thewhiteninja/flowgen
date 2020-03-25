import time

import bitstring

from modules.protocols.ethernet import Ethernet

PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


class PcapFile:

    def write_header(self):
        self.file.write(bitstring.pack("""
         uintbe:32, uintbe:16, uintbe:16, uintbe:32, uintbe:32, uintbe:32, uintbe:32""",
                                       PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER,
                                       PCAP_LOCAL_CORECTIN,
                                       PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, PCAP_DATA_LINK_TYPE).tobytes())

    def __init__(self, filename):
        self.file = open(filename, "wb")
        self.write_header()

    def add(self, packet):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(packet)
        self.file.write(
            bitstring.pack("uintbe:32, uintbe:32, uintbe:32, uintbe:32", ts_sec, ts_usec, length, length).tobytes())
        self.file.write(packet)

    def add_flow_udp(self, src, src_port, dest, dest_port, data):
        p = Ethernet(src.mac, dest.mac). \
            IPv4(src.ip, dest.ip). \
            UDP(src_port, dest_port). \
            Payload(data.pack()).pack()
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(p)
        self.file.write(
            bitstring.pack("uintbe:32, uintbe:32, uintbe:32, uintbe:32", ts_sec, ts_usec, length, length).tobytes())
        self.file.write(p)

    def close(self):
        if self.file is not None:
            self.file.close()
