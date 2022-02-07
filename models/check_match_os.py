import logging 

class CheckMatchOS:
    def __init__(self):
        pass

    def __calculate_score(self, fingerprint, other):
        """
        Compare a single print with another and return score 
        """
        return (fingerprint.T2.calculate_nmap_score(2, other.T2) +
                fingerprint.T3.calculate_nmap_score(3, other.T3) +
                fingerprint.T4.calculate_nmap_score(4, other.T4) +
                fingerprint.T5.calculate_nmap_score(5, other.T5) +
                fingerprint.T6.calculate_nmap_score(6, other.T6) +
                fingerprint.T7.calculate_nmap_score(7, other.T7) +
                fingerprint.IE.calculate_nmap_score(other.IE))

    def find_matching_os(self, target_fingerprint, fingerprints_db):
        """
        Iterate over fingerprint DB and find fingerprint with highest score
        """
        match_fingerprint = None
        max_score = 0

        for f in fingerprints_db:
            score = self.__calculate_score(f, target_fingerprint)
            if score > max_score:
                match_fingerprint = f
                max_score = score

        logging.info(f'Top Match Score: {max_score}\nMatched {str(match_fingerprint)}\n')
        return match_fingerprint