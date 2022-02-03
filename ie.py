from scapy.all import *

class IETest():
    def __init__(self, utils):
        self.utils = utils

    def get_closed_port(self):
        return random.randint(20000, 30000) 
	
    def get_random_ipid(self):
        return random.randint(20000, 30000) 

    def get_random_request_id(self):
        return random.randint(10000, 20000)
        
    def run_icmp_tests(self, ip, verbose=False):
        # Run Test
        ipid = self.get_random_ipid()
        reqid = self.get_random_request_id()

        p1 = IP(dst=ip, flags='DF', tos=0, id=ipid)/ICMP(code=9, seq=295, id=reqid)/Raw(load='A' * 120)
        r1 = self.utils.send_test_packet(p1, 'IE1', verbose)

        p2 = IP(dst=ip, tos=4, id=ipid+1)/ICMP(code=0, seq=296, id=reqid+1)/Raw(load='B' * 150)
        r2 = self.utils.send_test_packet(p2, 'IE2', verbose)

        # Create Test String Line
        if r1 and r2:
            s = 'IE('
        
            if 'DF' not in r1[IP].flags and 'DF' not in r2[IP].flags:
                s += 'DFI=N%'
            elif p1[IP].flags.DF == r1[IP].flags.DF and p2[IP].flags.DF == r2[IP].flags.DF:
                s += 'DFI=S%'
            elif 'DF' in r1[IP].flags and 'DF' in r2[IP].flags:
                s += 'DFI=Y%'
            else:
                s += 'DFI=O%'

            s += 'TG=' + hex(self.utils.get_initial_ttl_guess(r1[IP].ttl))[2:].upper() + '%'

            if r1[ICMP].code == 0 and r2[ICMP].code == 0:
                s += 'CD=Z)'
            elif r1[ICMP].code == p1[ICMP].code and r2[ICMP].code == p2[ICMP].code:
                s += 'CD=S)'
        else:
            s = 'IE(R=N)'

        return s + '\n'
