import logging 

class CheckMatchOS:
    def __init__(self):
        pass

    def check_match_os(self, unknown_fingerprint, fingerprints_db):
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
