# flowgen

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](#)
[![Language: Python](https://img.shields.io/badge/Language-Python-brightgreen.svg?tyle=flat-square)](#)
<br />

Flowgen generates a pcap file containing netflows described in a JSON file.
It can be used to test any tools or detection methods based on netflow.

Pcap can be replay by [TCPReplay][1].

[1]: https://github.com/appneta/tcpreplay

## Usage

    Usage: main.py command -f flows
    
    Command:
          generate        : Generate Pcap containing netflows
    
    Options:
          -h, --help      : Show help
          -f, --flows     : Input file (JSON flows) - required
          -o, --output    : Output file (default: output.pcap)
          -s, --sensor    : Flow sensor (IP:PORT)
          -c, --collector : Flow collector (IP:PORT)
          -v, --version   : Flow version (default: 9)
          --strict        : Disable flow autocompletion

## Limitations

- Netflow V9 only.
- 30 supported fields

    |               |               |                |               |                   |                     |
    | ------------- | ------------- | -------------- | ------------- | ----------------- | ------------------- |
    | IN_BYTES      | IN_PKTS       | FLOWS          | PROTOCOL      | IP_TOS            | TCP_FLAGS           |
    | L4_SRC_PORT   | IPV4_SRC_ADDR | INPUT_SNMP     | L4_DST_PORT   | IPV4_DST_ADDR     | IPV4_DST_MASK       |
    | OUTPUT_SNMP   | IPV4_NEXT_HOP | SRC_AS         | DST_AS        | BGP_IPV4_NEXT_HOP | MUL_DST_PKTS        |
    | MUL_DST_BYTES | LAST_SWITCHED | FIRST_SWITCHED | OUT_BYTES     | OUT_PKTS          | MIN_PKT_LNGTH       |
    | MAX_PKT_LNGTH | IPV6_SRC_ADDR | IPV6_DST_ADDR  | IPV6_SRC_MASK | IPV6_DST_MASK     | IP_PROTOCOL_VERSION |


## Output examples

```
cat example_flows.json
    
[
  {
    "IPV6_SRC_ADDR": "fe80::5153:e252:7215:3e53",
    "IPV6_DST_ADDR": "ff02::1:3",
    "IN_BYTES": 200000000,
    "IN_PKTS": 200000,
    "L4_SRC_PORT": 45543,
    "L4_DST_PORT": 8888,
    "PROTOCOL": 6
  }
]
```
 
```
./flowgen/main.py generate -f example_flows.json --sensor 10.83.178.113 --collector 10.83.178.126

[+] Loading flows from example_flows.json
[+] Building flow template
[+] Building flow data
    fe80::5153:e252:7215:3e53:45543 --[190.73 MB]--> ff02::1:3:8888 
[+] Writing to output.pcap    
```

<p align="center">
  <img alt="example" src="output.png">
</p>
