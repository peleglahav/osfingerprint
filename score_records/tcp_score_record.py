from models.options_format import OptionsFormat

TESTS_POINTS = [
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
]

class TCPScoreRecord():
    def __init__(self, utils ,test='T?(R=%DF=%T=%TG=%W=%S=%A=%F=%O=%RD=%Q=)'):
        self.utils = utils
        params = self.utils.split_db_test_string_to_params(test)

        self.responsed = params['R'] # Y / N
        if 'Y' in params['R']:
            self.dont_fragment = params['DF'] # Y / N
            self.ttl = [int(value, 16) for value in params['TG']]
            self.tcp_window_size = [int(value, 16) for value in params['W']]
            
            self.seq = params['S'] # Z / A / A+ / O
            self.ack = params['A'] # Z / S / S+ / O
            self.tcp_flags = params['F'] # E / U / A / P / R / S / F

            self.tcp_options = OptionsFormat()
            self.tcp_options.create_options_from_str(params['O'][0] if 'O' in params else '')
            self.rst_data_crc32 = [int(value, 16) for value in params['RD']]
            self.tcp_miscellaneous = params['Q'] if 'Q' in params else None
    
    def calculate_nmap_score(self, number, other):
        """
        Scoring method for NMAP TCP test
        Implemented as stated in NMAP Documentation
        """
        number -= 2
        score = 0
        if 'N' in self.responsed and 'N' in other.responsed:
            score += TESTS_POINTS[number]['R']
        elif 'Y' in self.responsed and 'Y' in other.responsed:
            if self.utils.is_fields_match(self.dont_fragment, other.dont_fragment):
                score += TESTS_POINTS[number]['DF']
            if self.utils.is_fields_match(self.ttl, other.ttl):
                score += TESTS_POINTS[number]['TG']
            if self.utils.is_fields_match(self.tcp_window_size, other.tcp_window_size):
                score += TESTS_POINTS[number]['W']
            if self.utils.is_fields_match(self.seq, other.seq):
                score += TESTS_POINTS[number]['S']
            if self.utils.is_fields_match(self.ack, other.ack):
                score += TESTS_POINTS[number]['A']
            if self.utils.is_fields_match(self.tcp_flags, other.tcp_flags):
                score += TESTS_POINTS[number]['F']
            if self.utils.is_fields_match(self.rst_data_crc32, other.rst_data_crc32):
                score += TESTS_POINTS[number]['RD']
            if self.utils.is_fields_match(self.tcp_miscellaneous, other.tcp_miscellaneous):
                score += TESTS_POINTS[number]['Q']

            if self.tcp_options.is_equal(other.tcp_options):
                score += TESTS_POINTS[number]['O']
        return score

    def __repr__(self):
        return self.test_str + '\n'
