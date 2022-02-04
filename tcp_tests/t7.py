from scapy.all import *

class t7(object):
    def __init__(self, utils):
        self.number = 7
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=port, flags='FPU', window=65535, options=T7_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T7', verbose=verbose)
        return (p, r)
