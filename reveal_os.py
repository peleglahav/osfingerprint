import argparse
import logging
from scapy.all import *
from test_runs.run_tcp import TCPTest
from test_runs.run_icmp import IETest
from utils.db_utils import DBUtils
from utils.packet_utils import PacketUtils
from models.check_match_os import CheckMatchOS
from models.fingerprint_record import FingerprintRecord

DB_PATH = 'data\os_db.txt'

def main():
    # Parse ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="The IP address of the remote target")
    parser.add_argument("--explain", help="Show high explainabily of product test requests", action="store_true")
    args = parser.parse_args()

    # Set logging
    logging_level = logging.DEBUG if args.explain else logging.INFO
    logging.basicConfig(format='%(asctime)s | %(levelname)s\t| %(message)s', datefmt="%Y-%m-%d %H:%M:%S", level=logging_level)

    #Init utils 
    db_utils = DBUtils()
    packet_utils = PacketUtils()

    #Init DB
    fingerprints_db = []
    db_utils.parse_os_db(DB_PATH, fingerprints_db) 

    #Run Tests
    tcp_test = TCPTest(packet_utils)
    fingerprint = tcp_test.run_tcp_tests(args.target, args.explain)
    
    icmp_test = IETest(packet_utils)
    fingerprint += icmp_test.run_icmp_tests(args.target, args.explain)
    
    # Match Results
    logging.info(f'\n\nMy test results {fingerprint}')
    target_fingerprint = FingerprintRecord(db_utils, fingerprint)
    checker = CheckMatchOS()
    checker.check_match_os(target_fingerprint, fingerprints_db)


if __name__ == "__main__":
    main()