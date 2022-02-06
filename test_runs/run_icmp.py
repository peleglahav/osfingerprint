from scapy.all import *
from icmp_tests.ie_p1 import IEP1
from icmp_tests.ie_p2 import IEP2

class IETest():
    def __init__(self, utils):
        self.utils = utils

    def run_icmp_tests(self, ip):
        ip_id = random.randint(20000, 30000) # Get a random IP ID
        req_id = random.randint(10000, 20000) # Get a random request ID

        ie1 = IEP1(self.utils)
        packet1, res1 = ie1.test(ip, ip_id, req_id)
        ie2 = IEP2(self.utils)
        packet2, res2 = ie2.test(ip, ip_id+1, req_id+1)

        if res1 and res2:
            s = 'IE('
        
            if 'DF' not in res1[IP].flags and 'DF' not in res2[IP].flags:
                s += 'DFI=N%'
            elif packet1[IP].flags.DF == res1[IP].flags.DF and packet2[IP].flags.DF == res2[IP].flags.DF:
                s += 'DFI=S%'
            elif 'DF' in res1[IP].flags and 'DF' in res2[IP].flags:
                s += 'DFI=Y%'
            else:
                s += 'DFI=O%'

            s += 'TG=' + hex(self.utils.get_initial_ttl_guess(res1[IP].ttl))[2:].upper() + '%'

            if res1[ICMP].code == 0 and res2[ICMP].code == 0:
                s += 'CD=Z)'
            elif res1[ICMP].code == packet1[ICMP].code and res2[ICMP].code == packet2[ICMP].code:
                s += 'CD=S)'
        else:
            s = 'IE(R=N)'

        return s + '\n'
