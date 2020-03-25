#!/usr/bin/env python
import json
import os
import platform
import sys
import time

from modules.endpoint import Endpoint
from modules.payloads.netflow_v9 import *
from modules.pcapfile import PcapFile
from modules.utils import random_ephemeral_port

OPTIONS_COMMAND = "generate"
STRICT = False
VERSION = 9
OPTIONS_OUTPUT_FILE = None
OPTIONS_INPUT_FILE = None
ENDPOINT_SENSOR, PORT_SENSOR = None, random_ephemeral_port()
ENDPOINT_COLLECTOR, PORT_COLLECTOR = None, 2055


def usage():
    print("Usage: " + os.path.basename(sys.argv[0]) + ' command -f flows')
    print()
    print("Command:")
    print("      generate        : Generate Pcap containing netflows")
    print()
    print("Options:")
    print("      -h, --help      : Show help")
    print("      -f, --flows     : Input file (JSON flows) - required")
    print("      -o, --output    : Output file (default: output.pcap)")
    print("      -s, --sensor    : Flow sensor (IP:PORT)")
    print("      -c, --collector : Flow collector (IP:PORT)")
    print("      --strict        : Disable flow autocompletion")
    print()
    sys.exit(0)


def parse_args():
    global OPTIONS_INPUT_FILE, OPTIONS_OUTPUT_FILE, ENDPOINT_SENSOR, ENDPOINT_COLLECTOR, PORT_SENSOR, PORT_COLLECTOR, STRICT, VERSION, OPTIONS_COMMAND
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] in ["-h", "--help"]:
            usage()
        elif sys.argv[i] in ["-f", "--flows"]:
            OPTIONS_INPUT_FILE = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] in ["-o", "--output"]:
            OPTIONS_OUTPUT_FILE = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] in ["--strict"]:
            STRICT = True
        elif sys.argv[i] in ["-s", "--sensor"]:
            sp = sys.argv[i + 1].split(":")
            ENDPOINT_SENSOR = sp[0]
            if len(sp) > 1:
                PORT_SENSOR = int(sp[1])
            i += 1
        elif sys.argv[i] in ["-c", "--collector"]:
            sp = sys.argv[i + 1].split(":")
            ENDPOINT_COLLECTOR = sp[0]
            if len(sp) > 1:
                PORT_COLLECTOR = int(sp[1])
            i += 1
        else:
            OPTIONS_COMMAND = sys.argv[i + 1]
            i += 1
        i += 1
    if OPTIONS_OUTPUT_FILE is None:
        OPTIONS_OUTPUT_FILE = "output.pcap"


def load_flows(filename):
    print("[+] Loading flows from %s" % os.path.basename(filename))
    with open(filename, "r") as f:
        data = json.load(f)
        if len(data) > 0:
            ref = data[0].keys()
            if len(data) > 1:
                i = 2
                for flow in data[1:]:
                    if ref != flow.keys():
                        print("[!] Different set of fields in flow %s" % i)
                        return None
                    i += 1
        return data


def create_netflow_packet():
    if VERSION == 9:
        return NetFlowV9Packet()
    else:
        raise Exception("Unsupported flow version %s" % str(VERSION))


def create_netflow_template(flow, strict_mode):
    if VERSION == 9:
        return NetFlowV9Template(flow, strict_mode)
    else:
        raise Exception("Unsupported flow template version %s" % str(VERSION))


def create_netflow_flow(flow, strict_mode):
    if VERSION == 9:
        return NetFlowV9Flow(flow, strict_mode)
    else:
        raise Exception("Unsupported flow template version %s" % str(VERSION))


def create_netflow_set(id=None):
    if VERSION == 9:
        if id == NetFlowID.TemplateAuto:
            return NetFlowV9Set(NetFlowID.TemplateV9)
        else:
            return NetFlowV9Set(id)
    else:
        raise Exception("Unsupported flow template version %s" % str(VERSION))


def process(flows, strict_mode):
    pkt = create_netflow_packet()

    print("[+] Building flow template")

    flowset_template = create_netflow_set(id=NetFlowID.TemplateAuto)
    flowset_template.add_flow(create_netflow_template(flows[0], STRICT))
    pkt.add_flowset(flowset_template)

    print("[+] Building flow data")
    flowset = create_netflow_set()
    i = 1
    for flow in flows:
        nf = create_netflow_flow(flow, strict_mode)
        flowset.add_flow(nf)
        print("   %2d : %s" % (i, nf))
        i += 1
    pkt.add_flowset(flowset)

    print("[+] Writing to %s" % OPTIONS_OUTPUT_FILE)
    f = PcapFile(OPTIONS_OUTPUT_FILE)
    f.add_flow_udp(
        Endpoint(ip=ENDPOINT_SENSOR),
        PORT_SENSOR,
        Endpoint(ip=ENDPOINT_COLLECTOR),
        PORT_COLLECTOR,
        pkt)
    f.close()


def edit(filename):
    pass


def main():
    print("Starting %s at %s (%s version)\n" % (
        os.path.basename(sys.argv[0]), time.asctime(time.localtime(time.time())), platform.architecture()[0]))

    parse_args()
    if OPTIONS_COMMAND == "generate":
        if OPTIONS_INPUT_FILE is None:
            print("[!] Missing input file option")
            return
        elif ENDPOINT_SENSOR is None:
            print("[!] Missing sensor option")
            return
        elif ENDPOINT_COLLECTOR is None:
            print("[!] Missing collector option")
            return

        flows = load_flows(OPTIONS_INPUT_FILE)
        if flows is not None:
            process(flows, STRICT)
    

if __name__ == '__main__':
    main()
