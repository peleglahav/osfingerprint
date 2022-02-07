from scapy.all import *
from tcp_tests.tbase import TBase

class T2(TBase):
    def __init__(self, utils):
        super().__init__(utils)
        self.number = 2
        self.common_options = self.common_options + [('WScale', 10)]

    def test(self, ip, port):
        """
        Implementation of T2 test as stated in NMAP
        """
        ip = IP(dst=ip, flags='DF')
        sequence_number=random.randint(20000, 30000)
        acknowledgement=random.randint(20000, 30000)
        tcp = TCP(sport=13337, dport=port, window=128, options=self.common_options, seq=sequence_number, ack=acknowledgement)
        
        p = ip/tcp
        r = self.utils.send_test_packet(p, 'T2')
        return (p, r)