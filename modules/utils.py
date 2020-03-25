import random


def random_mac_address(vendor=0):
    return vendor << 24 | random.randint(0, 0xffffff)


def random_ephemeral_port():
    return random.randint(32768, 61000)


def humansize(nbytes):
    suffixes = ['Bs', 'KB', 'MB', 'GB', 'TB', 'PB']
    if nbytes == 0:
        return '0 B'
    i = 0
    while nbytes >= 1024 and i < len(suffixes) - 1:
        nbytes /= 1024.0
        i += 1
    return '%.02f %s' % (nbytes, suffixes[i])
