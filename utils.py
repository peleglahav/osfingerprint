import logging 
from fingerprint_record import FingerprintRecord
from options_format import OptionsFormat

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

def check_match_os(unknown_fingerprint, fingerprints_db):
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

def parse_os_db(db_path, fingerprints_db):
    with open(db_path, 'rt') as db_file:
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