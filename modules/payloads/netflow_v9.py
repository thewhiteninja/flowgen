import bitstring
from netaddr import IPAddress

from modules.constants import NetFlowTemplateFieldID, NetFlowID
from modules.utils import humansize

ID = 0
SIZE = 1
NAME = 2


class NetFlowV9Packet:
    sequence = 0

    def __init__(self):
        self.version = 9
        self.count = 0
        self.uptime = 0
        self.timestamp = NetFlowV9Packet.sequence * 10
        self.sequence = NetFlowV9Packet.sequence
        NetFlowV9Packet.sequence += 1
        self.source_id = 0
        self.flowsets = []

    def add_flowset(self, flowset):
        self.flowsets.append(flowset)
        self.count += 1

    def pack(self):
        ret = bitstring.pack("uintbe:16, uintbe:16, uintbe:32, uintbe:32, uintbe:32, uintbe:32", self.version,
                             self.count, self.uptime,
                             self.timestamp, self.sequence, self.source_id).tobytes()
        for flowset in self.flowsets:
            ret += flowset.pack()
        return ret


class NetFlowV9Set:

    def __len__(self):
        return self.length

    def __init__(self, id=None):
        if id is None:
            self.id = None
        else:
            self.id = id.value
        self.length = 0x4
        self.flows = []

    def add_flow(self, flow):
        if self.id is None:
            if flow.get_field_by_id(NetFlowTemplateFieldID.IPV4_SRC_ADDR) is not None:
                self.id = NetFlowID.DataIPv4.value
            elif flow.get_field_by_id(NetFlowTemplateFieldID.IPV6_SRC_ADDR) is not None:
                self.id = NetFlowID.DataIPv6.value
        self.flows.append(flow)
        self.length += len(flow)

    def pack(self):
        ret = bitstring.pack("uintbe:16, uintbe:16", self.id, self.length).tobytes()
        for flow in self.flows:
            ret += flow.pack()
        return ret


def get_field_definition_by_name(name):
    for field in NetFlowTemplateFieldID:
        if field.value[NAME] == name:
            return field
    return None


class NetFlowV9Flow:

    def __len__(self):
        l = 0
        for field in self.fields:
            l += field.value[SIZE]
        return l

    def get_field_by_id(self, id):
        if id in self.fields:
            return self.fields[id]
        return None

    def __str__(self):
        ip_src_field = self.get_field_by_id(NetFlowTemplateFieldID.IPV4_SRC_ADDR)
        if ip_src_field is None:
            ip_src_field = self.get_field_by_id(NetFlowTemplateFieldID.IPV6_SRC_ADDR)
        ip_src = IPAddress(ip_src_field)

        ip_dst_field = self.get_field_by_id(NetFlowTemplateFieldID.IPV4_DST_ADDR)
        if ip_dst_field is None:
            ip_dst_field = self.get_field_by_id(NetFlowTemplateFieldID.IPV6_DST_ADDR)
        ip_dst = IPAddress(ip_dst_field)

        port_src = self.get_field_by_id(NetFlowTemplateFieldID.L4_SRC_PORT)
        port_dst = self.get_field_by_id(NetFlowTemplateFieldID.L4_DST_PORT)
        bytes_data = self.get_field_by_id(NetFlowTemplateFieldID.IN_BYTES)
        return "%s:%-5d --[%s]--> %s:%-5d" % (ip_src, port_src, humansize(bytes_data), ip_dst, port_dst)

    def __init__(self, fields, strict_mode):
        self.len = 0
        ip_version = 4
        self.fields = dict()
        for fieldname, fieldvalue in fields.items():
            field = get_field_definition_by_name(fieldname)
            if field is not None:
                if fieldname in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "IPV6_SRC_ADDR", "IPV6_DST_ADDR"]:
                    fieldvalue = int(IPAddress(fieldvalue))
                    ip_version = 4
                if fieldname in ["IPV6_SRC_ADDR", "IPV6_DST_ADDR"]:
                    fieldvalue = int(IPAddress(fieldvalue))
                    ip_version = 6
                self.fields[field] = fieldvalue
            else:
                raise Exception("Unsupported template field %s" % fieldname)
        if not strict_mode:
            if NetFlowTemplateFieldID.TCP_FLAGS not in self.fields:
                self.fields[NetFlowTemplateFieldID.TCP_FLAGS] = 0
            if NetFlowTemplateFieldID.IP_TOS not in self.fields:
                self.fields[NetFlowTemplateFieldID.IP_TOS] = 0
            if NetFlowTemplateFieldID.INPUT_SNMP not in self.fields:
                self.fields[NetFlowTemplateFieldID.INPUT_SNMP] = 0
            if NetFlowTemplateFieldID.OUTPUT_SNMP not in self.fields:
                self.fields[NetFlowTemplateFieldID.OUTPUT_SNMP] = 0
            if NetFlowTemplateFieldID.IP_PROTOCOL_VERSION not in self.fields:
                self.fields[NetFlowTemplateFieldID.IP_PROTOCOL_VERSION] = ip_version

    def pack(self):
        b = b""
        for field, field_value in self.fields.items():
            if field.value[SIZE] == 16:
                b += bitstring.pack("uintbe:128", field_value).tobytes()
            elif field.value[SIZE] == 4:
                b += bitstring.pack("uintbe:32", field_value).tobytes()
            elif field.value[SIZE] == 2:
                b += bitstring.pack("uintbe:16", field_value).tobytes()
            elif field.value[SIZE] == 1:
                b += bitstring.pack("uintbe:8", field_value).tobytes()
        return b


class NetFlowV9Template:

    def __len__(self):
        return 4 + 4 * len(self.fields)

    def __init__(self, fields, strict_mode):
        self.id = None
        for fieldname in fields:
            if fieldname in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR"]:
                self.id = NetFlowID.DataIPv4.value
                break
            elif fieldname in ["IPV6_SRC_ADDR", "IPV6_DST_ADDR"]:
                self.id = NetFlowID.DataIPv6.value
                break
        if self.id is None:
            raise Exception("Missing IP version field for creating template")

        self.fields = []
        for fieldname in fields:
            field = get_field_definition_by_name(fieldname)
            if field is not None:
                self.fields.append(field)
            else:
                raise Exception("Unsupported template field %s" % fieldname)

        if not strict_mode:
            if NetFlowTemplateFieldID.TCP_FLAGS not in self.fields:
                self.fields.append(NetFlowTemplateFieldID.TCP_FLAGS)
            if NetFlowTemplateFieldID.IP_TOS not in self.fields:
                self.fields.append(NetFlowTemplateFieldID.IP_TOS)
            if NetFlowTemplateFieldID.INPUT_SNMP not in self.fields:
                self.fields.append(NetFlowTemplateFieldID.INPUT_SNMP)
            if NetFlowTemplateFieldID.OUTPUT_SNMP not in self.fields:
                self.fields.append(NetFlowTemplateFieldID.OUTPUT_SNMP)
            if NetFlowTemplateFieldID.IP_PROTOCOL_VERSION not in self.fields:
                self.fields.append(NetFlowTemplateFieldID.IP_PROTOCOL_VERSION)

    def pack(self):
        ret = bitstring.pack("uintbe:16, uintbe:16", self.id, len(self.fields)).tobytes()
        for field in self.fields:
            ret += bitstring.pack("uintbe:16, uintbe:16", field.value[0], field.value[1]).tobytes()
        return ret
