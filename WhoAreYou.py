import argparse
import logging
from scapy.all import *
from t2_7 import TTest
from ie import IETest
from db_utils import DBUtils
from fingerprint_record import FingerprintRecord

def main():
    # Parse ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="IP address or Domain of the remote target")
    parser.add_argument("--verbose", help="Increase logging verbosity", action="store_true")
    args = parser.parse_args()

    # Set logging
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(asctime)s | %(levelname)s\t| %(message)s', datefmt="%Y-%m-%d %H:%M:%S", level=logging_level)


    #Utils 
    utils = DBUtils()

    #Init DB
    fingerprints_db = []
    utils.parse_os_db('os_db.txt', fingerprints_db) 

    # Run Tests
    tcp_test = TTest(utils)
    fingerprint = tcp_test.run_tcp_tests(args.target, args.verbose)
    #fingerprint = run_tcp_tests(args.target, args.verbose)
    icmp_test = IETest(utils)
    fingerprint += icmp_test.run_icmp_tests(args.target, args.verbose)
    
    # Match Results
    logging.info(f'My test {fingerprint}')
    utils.check_match_os(FingerprintRecord(utils, fingerprint), fingerprints_db)


if __name__ == "__main__":

    main()
