import logging

from scapy.all import *

from os_db_parser import *


def get_closed_port():
    return random.randint(20000, 30000) 

def check_open_tcp_port(target, verbose=False):
    return 443
    for port in range(100,65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        logging.info('Scanning port: {}'.format(port))
        # returns an error indicator
        result = s.connect_ex((target,port))
        if result ==0:
            print("Port {} is open".format(port))
            return port
        s.close()

def send_test_packet(packet, test_name, verbose=False):
    logging.info(f'############ Start: {test_name} ############')
    r = sr1(packet, verbose=verbose, timeout=2)
    if verbose:
        if r:
            logging.info('Answer: {}'.format(r.summary()))
        else:
            logging.info('No Answer Received!')
    logging.info(f'############ End: {test_name} ############')
    return r

COMMON_OPTIONS = [
    ('NOP', None),
    ('MSS', 265),
    ('Timestamp', (0xffffffff, 0x0)),
    ('SAckOK', ''),
]

T2_6_OPTIONS = COMMON_OPTIONS + [('WScale', 10)]
T7_OPTIONS = COMMON_OPTIONS + [('WScale', 15)]

class t2(object):
    def __init__(self):
        self.number = 2

    def test(self, ip, open_port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=open_port, window=128, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T2', verbose=verbose)
        return (p, r)
    
class t3(object):
    def __init__(self):
        self.number = 3
        
    def test(self, ip, open_port, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=open_port, flags='SUPF', window=256, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T3', verbose=verbose)
        return (p, r)

class t4(object):
    def __init__(self):
        self.number = 4

    def test(self, ip, open_port, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=open_port, flags='A', window=1024, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T4', verbose=verbose)
        return (p, r)
    
class t5(object):
    def __init__(self):
        self.number = 5
        
    def test(self, ip, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=get_closed_port(), flags='S', window=31337, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T5', verbose=verbose)
        return (p, r)

class t6(object):
    def __init__(self):
        self.number = 6

    def test(self, ip, verbose=False):
        p = IP(dst=ip, flags='DF')/TCP(sport=13337, dport=get_closed_port(), flags='A', window=32768, options=T2_6_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T6', verbose=verbose)
        return (p, r)

class t7(object):
    def __init__(self):
        self.number = 7
        
    def test(self, ip, verbose=False):
        p = IP(dst=ip)/TCP(sport=13337, dport=get_closed_port(), flags='FPU', window=65535, options=T7_OPTIONS, seq=random.randint(20000, 30000), ack=random.randint(20000, 30000))
        r = send_test_packet(p, 'T7', verbose=verbose)
        return (p, r)

def run_tcp_tests(ip, verbose=False):
    parse_os_db('os_db.txt')

    open_port = check_open_tcp_port(ip, verbose)

    open_port_tests = [t2, t3, t4]
    closed_port_tests = [t5, t6, t7]
    
    fingerprint = 'Fingerprint Testing...\n'

    for test_class in open_port_tests:
        test_case = test_class()
        packet_send, packet_received = test_case.test(ip, open_port, verbose)

        fingerprint += get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'
        
    for test_class in closed_port_tests:
        test_case = test_class()
        packet_send, packet_received = test_case.test(ip, verbose)

        fingerprint += get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'

    return fingerprint