class TBase:
    """
    Base class for all TCP Tests (T2-T7)
    """
    def __init__(self, utils):
        self.number = 0
        self.utils= utils
        self.common_options= [('NOP', None), ('MSS', 265), ('Timestamp', (0xffffffff, 0x0)), ('SAckOK', ''),]
    
    def test(self, ip, port):
        pass