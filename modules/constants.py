from enum import Enum


class NetFlowID(Enum):
    DataIPv4 = 1024
    DataIPv6 = 2048
    DataIPvAuto = 9999
    TemplateV9 = 0
    TemplateIPFIX = 2
    TemplateAuto = 9998


class NetFlowTemplateFieldID(Enum):
    IN_BYTES = (1, 4, "IN_BYTES")
    IN_PKTS = (2, 4, "IN_PKTS")
    FLOWS = (3, 4, "FLOWS")
    PROTOCOL = (4, 1, "PROTOCOL")
    IP_TOS = (5, 1, "IP_TOS")
    TCP_FLAGS = (6, 1, "TCP_FLAGS")
    L4_SRC_PORT = (7, 2, "L4_SRC_PORT")
    IPV4_SRC_ADDR = (8, 4, "IPV4_SRC_ADDR")
    IPV4_SRC_MASK = (9, 1, "IPV4_SRC_MASK")
    INPUT_SNMP = (10, 4, "INPUT_SNMP")
    L4_DST_PORT = (11, 2, "L4_DST_PORT")
    IPV4_DST_ADDR = (12, 4, "IPV4_DST_ADDR")
    IPV4_DST_MASK = (13, 1, "IPV4_DST_MASK")
    OUTPUT_SNMP = (14, 4, "OUTPUT_SNMP")
    IPV4_NEXT_HOP = (15, 4, "IPV4_NEXT_HOP")
    SRC_AS = (16, 2, "SRC_AS")
    DST_AS = (17, 2, "DST_AS")
    BGP_IPV4_NEXT_HOP = (18, 4, "BGP_IPV4_NEXT_HOP")
    MUL_DST_PKTS = (19, 4, "MUL_DST_PKTS")
    MUL_DST_BYTES = (20, 4, "MUL_DST_BYTES")
    LAST_SWITCHED = (21, 4, "LAST_SWITCHED")
    FIRST_SWITCHED = (22, 4, "FIRST_SWITCHED")
    OUT_BYTES = (23, 4, "OUT_BYTES")
    OUT_PKTS = (24, 4, "OUT_PKTS")
    MIN_PKT_LNGTH = (25, 2, "MIN_PKT_LNGTH")
    MAX_PKT_LNGTH = (26, 2, "MAX_PKT_LNGTH")
    IPV6_SRC_ADDR = (27, 16, "IPV6_SRC_ADDR")
    IPV6_DST_ADDR = (28, 16, "IPV6_DST_ADDR")
    IPV6_SRC_MASK = (29, 1, "IPV6_SRC_MASK")
    IPV6_DST_MASK = (30, 1, "IPV6_DST_MASK")
    IP_PROTOCOL_VERSION = (60, 1, "IP_PROTOCOL_VERSION")


class IPProtocol(Enum):
    TCP = 0x06
    UDP = 0x11


class IPFlag(Enum):
    DONT_FRAGMENT = 0x4000


class EtherType(Enum):
    IPv4 = 0x0800
    IPv6 = 0x86DD
