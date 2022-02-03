from t_test_record import TTestRecord
from ie_test_record import IETestRecord

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

    def calculate_match_score(self, other):
        return (self.T2.calculate_test_match_score(2, other.T2) +
                self.T3.calculate_test_match_score(3, other.T3) +
                self.T4.calculate_test_match_score(4, other.T4) +
                self.T5.calculate_test_match_score(5, other.T5) +
                self.T6.calculate_test_match_score(6, other.T6) +
                self.T7.calculate_test_match_score(7, other.T7) +
                self.IE.calculate_test_match_score(other.IE))


    def __repr__(self):
        return self.fingerprint_str

