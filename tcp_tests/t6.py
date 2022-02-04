from scapy.all import *
from tcp_tests.tbase import TBase

class T6(TBase):
    def __init__(self, utils):
        super().__init__(utils)
        self.number = 6
        self.common_options = self.common_options + [('WScale', 10)]

    def test(self, ip, port,verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, flags='A', window=32768, options=self.common_options, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T6', verbose=verbose)
        return (p, r)