from scapy.all import *

#TODO: ADD OPTIONS PANE

class t2(object):
    def __init__(self, utils):
        self.number = 2
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, window=128, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T2', verbose=verbose)
        return (p, r)