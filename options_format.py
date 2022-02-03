from string import hexdigits


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

