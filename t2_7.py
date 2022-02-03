from scapy.all import *

COMMON_OPTIONS = [
    ('NOP', None),
    ('MSS', 265),
    ('Timestamp', (0xffffffff, 0x0)),
    ('SAckOK', ''),
]

T2_6_OPTIONS = COMMON_OPTIONS + [('WScale', 10)]
T7_OPTIONS = COMMON_OPTIONS + [('WScale', 15)]

class t2(object):
    def __init__(self, utils):
        self.number = 2
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, window=128, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T2', verbose=verbose)
        return (p, r)
    
class t3(object):
    def __init__(self,utils):
        self.number = 3
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=port, flags='SUPF', window=256, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T3', verbose=verbose)
        return (p, r)

class t4(object):
    def __init__(self,utils):
        self.number = 4
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, flags='A', window=1024, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T4', verbose=verbose)
        return (p, r)
    
class t5(object):
    def __init__(self, utils):
        self.number = 5
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=port, flags='S', window=31337, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T5', verbose=verbose)
        return (p, r)

class t6(object):
    def __init__(self,utils):
        self.number = 6
        self.utils = utils

    def test(self, ip, port,verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=port, flags='A', window=32768, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T6', verbose=verbose)
        return (p, r)

class t7(object):
    def __init__(self, utils):
        self.number = 7
        self.utils = utils

    def test(self, ip, port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=port, flags='FPU', window=65535, options=T7_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = self.utils.send_test_packet(p, 'T7', verbose=verbose)
        return (p, r)

class TTest():
    def __init__(self, utils):
        self.utils = utils

    def run_tcp_tests(self, ip, verbose=False):
        open_port = 443

        open_port_tests = [t2, t3, t4]
        closed_port_tests = [t5, t6, t7]
        
        fingerprint = 'Fingerprint Testing...\n'

        for test_class in open_port_tests:
            test_case = test_class(self.utils)
            packet_send, packet_received = test_case.test(ip, open_port, verbose)

            fingerprint += self.utils.get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'
            
        for test_class in closed_port_tests:
            test_case = test_class(self.utils)
            closed_port = random.randint(20000, 30000)
            packet_send, packet_received = test_case.test(ip, closed_port, verbose)

            fingerprint += self.utils.get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'

        return fingerprint