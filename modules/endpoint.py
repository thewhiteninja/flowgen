import netaddr
from netaddr import IPAddress

from modules.utils import random_mac_address


class Endpoint:

    def __init__(self, ip, mac=None):
        self.ip = int(IPAddress(ip))
        if mac is None:
            mac = random_mac_address()
        self.mac = int(netaddr.EUI(mac))
