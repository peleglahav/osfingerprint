from scapy.all import *
from tcp_tests.tbase import TBase

class T2(TBase):
    def __init__(self, utils):
        super().__init__(utils)
        self.number = 2
        self.common_options = self.common_options + [('WScale', 10)]

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, window=128, options=self.common_options, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T2', verbose=verbose)
        return (p, r)