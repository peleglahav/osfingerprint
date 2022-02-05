from scapy.all import *

class IE1():
    def __init__(self, utils):
        self.utils = utils

    def test(self, ip, ip_id, req_id, verbose=False):
        p = IP(dst=ip, flags='DF', tos=0, id=ip_id)
        icmp = ICMP(code=9, seq=295, id=req_id)
        raw = Raw(load='A' * 120)

        packet = p/icmp/raw
        res = self.utils.send_test_packet(packet, 'IE1', verbose)
        return (packet, res)