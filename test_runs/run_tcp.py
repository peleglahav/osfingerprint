from scapy.all import *

from tcp_tests.t2 import T2
from tcp_tests.t3 import T3
from tcp_tests.t4 import T4
from tcp_tests.t5 import T5
from tcp_tests.t6 import T6
from tcp_tests.t7 import T7

class TCPTest():
    def __init__(self, utils):
        self.utils = utils

    def find_open_tcp_port(self, target):
        return 443 #for testing
        for port in range(80,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            logging.info('Scanning port: {}'.format(port))
            result = s.connect_ex((target,port))
            if result == 0: #Port is open!
                return port
            s.close()

    def run_opened_port_tests(self, ip, verbose):
        open_port_tests = [T2, T3, T4]
        open_port = self.find_open_tcp_port(ip)

        open_test_records = ""

        for test_class in open_port_tests:
            test_case = test_class(self.utils)
            packet_send, packet_received = test_case.test(ip, open_port, verbose)

            open_test_records += self.utils.get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'
        
        return open_test_records

    def run_closed_port_tests(self, ip, verbose):
        closed_port_tests = [T5, T6, T7]
        closed_test_records = ""
        
        for test_class in closed_port_tests:
            test_case = test_class(self.utils)
            closed_port = random.randint(20000, 30000)
            packet_send, packet_received = test_case.test(ip, closed_port, verbose)

            closed_test_records += self.utils.get_test_record_from_packet(test_case.number, packet_send, packet_received) + '\n'
        
        return closed_test_records

    def run_tcp_tests(self, ip, verbose=False):
        fingerprint = self.run_opened_port_tests(ip, verbose)

        fingerprint += self.run_closed_port_tests(ip, verbose)

        return fingerprint