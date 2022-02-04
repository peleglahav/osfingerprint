from scapy.all import *
from tcp_tests.tbase import TBase

class T7(TBase):
    def __init__(self, utils):
        super().__init__(utils)
        self.number = 7
        self.common_options = self.common_options + [('WScale', 15)]

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=port, flags='FPU', window=65535, options=self.common_options, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T7', verbose=verbose)
        return (p, r)