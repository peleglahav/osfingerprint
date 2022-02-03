from utils import split_db_test_string_to_params
from utils import is_fields_match

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