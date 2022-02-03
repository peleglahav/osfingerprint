from string import hexdigits

from scapy.all import *


fingerprints_db = []

'''
Fingerprint Record Example
---------------------------------------------------------
Fingerprint Microsoft Windows 10
T2(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
IE(DFI=N%T=3B-45%TG=40%CD=Z)
---------------------------------------------------------
'''

class OptionsFormat(object):
    def __init__(self):
        self.mss = 0
        self.nops = 0
        self.wscale = 0
        self.timestamp = False
        self.tsval = 0
        self.tsecr = 0
        self.sackok = False

        self.representation = ''

    def set_options_by_str(self, options):
        self.representation = options
        if options == '':
            return

        i = 0
        while True:
            if options[i] == 'N':
                self.nops += 1
            elif options[i] == 'M':
                i += 1
                self.mss = 0
                while options[i] in hexdigits:
                    self.mss = 16 * self.mss + int(options[i], 16)
                    i += 1
                    if i == len(options):
                        return
            elif options[i] == 'W':
                i += 1
                self.wscale = 0
                while options[i] in hexdigits:
                    self.wscale = 16 * self.wscale + int(options[i], 16)
                    i += 1
                    if i == len(options):
                        return
            elif options[i] == 'T':
                i += 1
                self.tsval = int(options[i], 16)
                i += 1
                self.tsecr = int(options[i], 16)
            elif options[i] == 'S':
                self.sackok = True
            elif options[i] == 'L':
                break
            
            i += 1
            if i == len(options):
                return

    def set_representation(self):
        s = ''
        
        if self.mss:
            s += 'M' + hex(self.mss)[2:].upper()
        s += 'N' * self.nops
        if self.wscale:
            s += 'W' + hex(self.wscale)[2:].upper()
        if self.timestamp:
            s += 'T' + hex(self.tsval)[2:] + hex(self.tsecr)[2:]
        if self.sackok:
            s += 'S'
        if s:
            s += 'L'
        
        self.representation = s

    def set_options_by_packet(self, options):
        for option in options:
            name = option[0]
            value = option[1]

            if name == 'MSS':
                self.mss = value
            elif name == 'NOP':
                self.nops += 1
            elif name == 'WScale':
                self.wscale = value
            elif name == 'Timestamp':
                self.timestamp = True
                if value[0]:
                    self.tsval = 1
                else:
                    self.tsval = 0

                if value[1]:
                    self.tsecr = 1
                else:
                    self.tsecr = 0
            elif name == 'SAckOK':
                self.sackok = True

        self.set_representation()

    def is_equal(self, other):
        return self.mss == other.mss and \
               self.nops == other.nops and \
               self.wscale == other.wscale and \
               self.tsval == other.tsval and \
               self.tsecr == other.tsecr and \
               self.sackok == other.sackok
               
    def get_score(self, other):
        score = 0
        if self.mss == other.mss:
            score += 0.5
        if self.nops == other.nops:
            score += 0.5
        if self.wscale == other.wscale:
            score += 0.5
        if self.tsval == other.tsval:
            score += 0.5
        if self.tsecr == other.tsecr:
            score += 0.5
        if self.sackok == other.sackok:
            score += 0.5
        return score

def get_initial_ttl_guess(ttl):
    if (ttl <= 32):
        return 32
    elif ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 255

def get_test_record_from_packet(number, packet_sent, packet_received):
    s = 'T' + str(number) + '('
    
    if packet_received:
        s += 'R=Y%'
        
        ip_part = packet_received[IP]

        if 'DF' in ip_part.flags:
            s += 'DF=Y%'
        else:
            s += 'DF=N%'

        s += 'TG=' + hex(get_initial_ttl_guess(ip_part.ttl))[2:].upper() + '%'

        tcp_part = packet_received[TCP]
        
        s += 'W=' + hex(tcp_part.window)[2:].upper() + '%'
        
        seq = tcp_part.seq
        ack = tcp_part.ack
        
        if seq == 0:
            s += 'S=Z%'
        elif seq == packet_sent[TCP].ack:
            s += 'S=A%'
        elif seq == packet_sent[TCP].ack + 1:
            s += 'S=A+%'
        else:
            s += 'S=O%'
        if ack == 0:
            s += 'A=Z%'
        elif ack == packet_sent[TCP].seq:
            s += 'A=S%'
        elif ack == packet_sent[TCP].seq + 1:
            s += 'A=S+%'
        else:
            s += 'A=O%'

        s_flags = ''
        if 'E' in tcp_part.flags:
            s_flags += 'E'
        if 'U' in tcp_part.flags:
            s_flags += 'U'
        if 'A' in tcp_part.flags:
            s_flags += 'A'
        if 'P' in tcp_part.flags:
            s_flags += 'P'
        if 'R' in tcp_part.flags:
            s_flags += 'R'
        if 'S' in tcp_part.flags:
            s_flags += 'S'
        if 'F' in tcp_part.flags:
            s_flags += 'F'

        if s_flags:
            s += 'F=' + s_flags + '%'

        s_options = OptionsFormat()
        s_options.set_options_by_packet(tcp_part.options)
        if s_options.representation:
            s += 'O=' + s_options.representation + '%'
        else:
            s += 'O=%'

        s += 'RD=0%'
        s += 'Q='
    else:
        s += 'R=N'

    s += ')'
    
    return s

TESTS_POINTS = [
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 100, 'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
    {'R': 80,  'DF': 20, 'T': 15, 'TG': 15, 'W': 25, 'S': 20, 'A': 20, 'F': 30, 'O': 10, 'RD': 20, 'Q': 20},
]

class TTestRecord():
    def __init__(self, test='T?(R=%DF=%T=%TG=%W=%S=%A=%F=%O=%RD=%Q=)'):
        params = split_db_test_string_to_params(test)

        self.responsed = params['R'] # 'Y' / 'N'
        if 'Y' in params['R']:
            self.dont_fragment = params['DF'] # 'Y' / 'N'
            self.ttl = [int(value, 16) for value in params['TG']]
            self.tcp_window_size = [int(value, 16) for value in params['W']]
            
            '''
            Seq test values:
                Z   = zero
                A   = same as ack
                A+  = ack + 1
                O   = other
            '''
            self.seq = params['S']

            '''
            ACK test values:
                Z   = zero
                S   = same as seq
                S+  = seq + 1
                O   = other
            '''
            self.ack = params['A']

            '''
            Flags. They must be in this order:
                E = ECN Echo
                U = Urgent
                A = Acknowledgement
                P = Push
                R = Reset
                S = Synchronize
                F = Final
            '''
            self.tcp_flags = params['F']

            self.tcp_options = OptionsFormat()
            self.tcp_options.set_options_by_str(params['O'][0] if 'O' in params else '')
            #self.tcp_options = params['O'] if 'O' in params else None
            self.rst_data_crc32 = [int(value, 16) for value in params['RD']]
            self.tcp_miscellaneous = params['Q'] if 'Q' in params else None
    
    def calculate_test_match_score(self, number, other):
        number -= 2
        score = 0
        if 'N' in self.responsed and 'N' in other.responsed:
            score += TESTS_POINTS[number]['R']
        elif 'Y' in self.responsed and 'Y' in other.responsed:
            if is_fields_match(self.dont_fragment, other.dont_fragment):
                score += TESTS_POINTS[number]['DF']
            if is_fields_match(self.ttl, other.ttl):
                score += TESTS_POINTS[number]['TG']
            if is_fields_match(self.tcp_window_size, other.tcp_window_size):
                score += TESTS_POINTS[number]['W']
            if is_fields_match(self.seq, other.seq):
                score += TESTS_POINTS[number]['S']
            if is_fields_match(self.ack, other.ack):
                score += TESTS_POINTS[number]['A']
            if is_fields_match(self.tcp_flags, other.tcp_flags):
                score += TESTS_POINTS[number]['F']
            if is_fields_match(self.rst_data_crc32, other.rst_data_crc32):
                score += TESTS_POINTS[number]['RD']
            if is_fields_match(self.tcp_miscellaneous, other.tcp_miscellaneous):
                score += TESTS_POINTS[number]['Q']

            if self.tcp_options.is_equal(other.tcp_options):
                score += TESTS_POINTS[number]['O']
        return score

    def __repr__(self):
        return self.test_str + '\n'

class FingerprintRecord():
    def __init__(self, fingerprint):
        self.fingerprint_str = fingerprint
        fingerprint_lines = fingerprint.split('\n')[:-1]
        self.fingerprint_name = fingerprint_lines[0].split('Fingerprint ')[-1]
        self.T2 = TTestRecord(fingerprint_lines[1])
        self.T3 = TTestRecord(fingerprint_lines[2])
        self.T4 = TTestRecord(fingerprint_lines[3])
        self.T5 = TTestRecord(fingerprint_lines[4])
        self.T6 = TTestRecord(fingerprint_lines[5])
        self.T7 = TTestRecord(fingerprint_lines[6])
        self.IE = IETestRecord(fingerprint_lines[7])

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

class IETestRecord():
    def __init__(self, test='IE(DFI=%T=%TG=%CD=)'):
        params = split_db_test_string_to_params(test)

        self.responsed = False
        if 'R' not in params:
            self.responsed = True
            self.dont_fragment = params['DFI']
            self.ttl = [int(value, 16) for value in params['TG']]
            self.reply_code = params['CD']
            
    def calculate_test_match_score(self, other):
        score = 0
        if not self.responsed and not other.responsed:
            score += 50
        elif self.responsed and other.responsed:
            score += 50
            if is_fields_match(self.dont_fragment, other.dont_fragment):
                score += 40
            if is_fields_match(self.ttl, other.ttl):
                score += 15
            if is_fields_match(self.reply_code, other.reply_code):
                score += 100
        return score

    def __repr__(self):
        return self.test_str + '\n'

def is_fields_match(self_field, other_field):
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
    

def split_db_test_string_to_params(test):
    params = {}
    for test_param in test[3:-1].split('%'):
        param_field, param_values = test_param.split('=')
        param_values = param_values.split('|')
        params[param_field] = param_values
    return params

def parse_os_db(db_path):
    with open(db_path, 'rb') as db_file:
        fingerprint = ''
        line = db_file.readline()
        while line != '':
            if line.startswith('Fingerprint '):
                fingerprint = line
            elif line[:3] in ['T2(', 'T3(', 'T4(', 'T5(', 'T6(', 'T7(', 'IE(',]:
                fingerprint += line
            elif line == '\n':
                fingerprints_db.append(FingerprintRecord(fingerprint))
                fingerprint = ''
            line = db_file.readline()

def check_match_os(unknown_fingerprint):
    match_fingerprint = None
    max_score = 0

    matching_scores = {}
    for f in fingerprints_db:
        score = f.calculate_match_score(unknown_fingerprint)
        if score > max_score:
            match_fingerprint = f
            max_score = score
            matching_scores[str(f)] = max_score

    logging.info('Best scores: '.format(matching_scores))
    for k, v in matching_scores.items():
        logging.info(f'Score: {v}\n{k}\n')

    return match_fingerprint


"""
parse_os_db('os_db.txt')
a = check_match_os(FingerprintRecord(
'''Fingerprint Microsoft Windows 10
T2(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
IE(DFI=N%T=3B-45%TG=40%CD=Z)
'''))

print(a)
"""