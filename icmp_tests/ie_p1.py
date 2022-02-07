from scapy.all import *

class IEP1():
    def __init__(self, utils):
        self.utils = utils

    def test(self, ip, ip_id, req_id):
        """
        Implementing the first ICMP Echo packet that will compose IE Test
        Packet params are as stated in NMAP Research
        """
        p = IP(dst=ip, flags='DF', tos=0, id=ip_id)
        icmp = ICMP(code=9, seq=295, id=req_id)
        raw = Raw(load='A' * 120)

        packet = p/icmp/raw
        res = self.utils.send_test_packet(packet, 'IE-P1')
        return (packet, res)