import argparse
import logging
import random

from scapy.all import *

from t2_7 import *
from ie import *

def main():
    # Parse ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="IP address or Domain of the remote target")
    parser.add_argument("--verbose", help="Increase logging verbosity", action="store_true")
    args = parser.parse_args()

    # Set logging
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(asctime)s | %(levelname)s\t| %(message)s', datefmt="%Y-%m-%d %H:%M:%S", level=logging_level)

    # Run Tests
    fingerprint = run_tcp_tests(args.target, args.verbose)
    fingerprint += run_icmp_tests(args.target, args.verbose)
    
    # Match Results
    logging.info(f'My test {fingerprint}')
    check_match_os(FingerprintRecord(fingerprint))

if __name__ == "__main__":
    main()