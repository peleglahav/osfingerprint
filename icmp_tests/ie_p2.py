from scapy.all import *

class IEP2():
    def __init__(self, utils):
        self.utils = utils

    def test(self, ip, ip_id, req_id):
        """
        Implementing the second ICMP Echo packet that will compose IE test
        Packet params are as stated in NMAP Research
        """
        p = IP(dst=ip, tos=4, id=ip_id+1)
        icmp = ICMP(code=0, seq=296, id=req_id+1)
        raw = Raw(load='B' * 150)

        packet = p/icmp/raw
        res = self.utils.send_test_packet(packet, 'IE-P2')
        return (packet, res)