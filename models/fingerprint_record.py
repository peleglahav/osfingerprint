from score_records.tcp_score_record import TCPScoreRecord
from score_records.ie_score_record import IEScoreRecord

class FingerprintRecord():
    """
    Holds the data that will define a fingerprint record both 
    in the database and in the target machine
    """
    def __init__(self, utils, fingerprint):
        self.fingerprint_str = fingerprint
        fingerprint_lines = fingerprint.split('\n')[:-1]
        self.fingerprint_name = fingerprint_lines[0].split('Fingerprint ')[-1]
        
        self.T2 = TCPScoreRecord(utils, fingerprint_lines[1])
        self.T3 = TCPScoreRecord(utils, fingerprint_lines[2])
        self.T4 = TCPScoreRecord(utils, fingerprint_lines[3])
        self.T5 = TCPScoreRecord(utils, fingerprint_lines[4])
        self.T6 = TCPScoreRecord(utils, fingerprint_lines[5])
        self.T7 = TCPScoreRecord(utils, fingerprint_lines[6])
        self.IE = IEScoreRecord(utils, fingerprint_lines[7])

    def __repr__(self):
        return self.fingerprint_str

