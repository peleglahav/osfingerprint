import logging 

class CheckMatchOS:
    def __init__(self):
        pass

    def __calculate_match_score(self, fingerprint, other):
        return (fingerprint.T2.calculate_test_match_score(2, other.T2) +
                fingerprint.T3.calculate_test_match_score(3, other.T3) +
                fingerprint.T4.calculate_test_match_score(4, other.T4) +
                fingerprint.T5.calculate_test_match_score(5, other.T5) +
                fingerprint.T6.calculate_test_match_score(6, other.T6) +
                fingerprint.T7.calculate_test_match_score(7, other.T7) +
                fingerprint.IE.calculate_test_match_score(other.IE))

    def check_match_os(self, unknown_fingerprint, fingerprints_db):
        match_fingerprint = None
        max_score = 0

        for f in fingerprints_db:
            score = self.__calculate_match_score(f, unknown_fingerprint)
            if score > max_score:
                match_fingerprint = f
                max_score = score

        #logging.info('Top match')
        logging.info(f'Top Match Score: {max_score}\nMatched {str(match_fingerprint)}\n')


        return match_fingerprint