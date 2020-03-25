import bitstring
import netaddr

from modules.constants import EtherType
from modules.protocols.ip import IPv4
from modules.utils import random_mac_address


class Ethernet:

    def __init__(self, mac_from=None, mac_to=None):
        self.encapsulated = None

        if mac_from is None:
            mac_from = random_mac_address()
        if mac_to is None:
            mac_to = random_mac_address()

        if isinstance(mac_from, int):
            self.mac_from = mac_from
        elif isinstance(mac_from, str):
            self.mac_from = int(netaddr.EUI(mac_from))

        if isinstance(mac_to, int):
            self.mac_to = mac_to
        elif isinstance(mac_to, str):
            self.mac_to = int(netaddr.EUI(mac_to))

        self.ether_type = EtherType.IPv4.value

    def pack(self, full=False):
        return bitstring.pack("uintbe:48, uintbe:48, uintbe:16", self.mac_from, self.mac_to, self.ether_type).tobytes()

    def IPv4(self, source, destination, ttl=64):
        self.encapsulated = IPv4(source, destination, ttl)
        self.encapsulated.parent = self
        self.ether_type = EtherType.IPv4.value
        return self.encapsulated
