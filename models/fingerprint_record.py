from test_records.t_test_record import TTestRecord
from test_records.ie_test_record import IETestRecord

class FingerprintRecord():
    def __init__(self, utils, fingerprint):
        self.fingerprint_str = fingerprint
        fingerprint_lines = fingerprint.split('\n')[:-1]
        self.fingerprint_name = fingerprint_lines[0].split('Fingerprint ')[-1]
        
        self.T2 = TTestRecord(utils, fingerprint_lines[1])
        self.T3 = TTestRecord(utils, fingerprint_lines[2])
        self.T4 = TTestRecord(utils, fingerprint_lines[3])
        self.T5 = TTestRecord(utils, fingerprint_lines[4])
        self.T6 = TTestRecord(utils, fingerprint_lines[5])
        self.T7 = TTestRecord(utils, fingerprint_lines[6])
        self.IE = IETestRecord(utils, fingerprint_lines[7])

    def __repr__(self):
        return self.fingerprint_str

