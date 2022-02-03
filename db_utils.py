import logging 
from scapy.all import *
from fingerprint_record import FingerprintRecord

class DBUtils():
    def __init__(self):
        pass
    
    def is_fields_match(self, self_field, other_field):
        if other_field is None and self_field is None:
            return True
        elif other_field is None and '' in self_field:
            return True
        elif self_field is None and '' in other_field:
            return True

        for value in other_field:
            if value in self_field:
                return True
        return False

    def split_db_test_string_to_params(self, test):
        params = {}
        for test_param in test[3:-1].split('%'):
            param_field, param_values = test_param.split('=')
            param_values = param_values.split('|')
            params[param_field] = param_values
        return params

    def parse_os_db(self, db_path, fingerprints_db):
        with open(db_path, 'rt', encoding="utf-8") as db_file:
            fingerprint = ''
            line = db_file.readline()
            while line != '':
                if line.startswith('Fingerprint '):
                    fingerprint = line
                elif line[:3] in ['T2(', 'T3(', 'T4(', 'T5(', 'T6(', 'T7(', 'IE(',]:
                    fingerprint += line
                elif line == '\n':
                    fingerprints_db.append(FingerprintRecord(DBUtils(), fingerprint))
                    fingerprint = ''
                line = db_file.readline()