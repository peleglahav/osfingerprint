import logging 
from scapy.all import *
from models.options_format import OptionsFormat

class PacketUtils():
    def __init__(self, explain):
        self.explain = explain
        pass

    def send_packet(self, packet, test_name):
        """
        Send the packet using scapy.
        Notice the log level of scapy and the fact that it sniffs in raw.
        """
        logging.info(f'Start: {test_name}')
        r = sr1(packet, verbose=self.explain, timeout=2) #Beggin emission. Finished sending 1 package. Received 1 packets, got 0 answers, remaining 1 packets
        if self.explain:
            if r:
                logging.info('Answer Received: {}'.format(r.summary()))
            else:
                logging.info('No Answer Received')
        logging.info(f'End: {test_name}')
        return r

    def guess_ttl(self, ttl):
        """
        Return a proximate TTL guessed based on common values
        """
        if (ttl <= 32):
            return 32
        elif ttl <= 64:
            return 64
        elif ttl <= 128:
            return 128
        else:
            return 255
    
    def create_record_from_packet(self, number, packet_sent, packet_received):
        """
        Create a test encoding string based on NMAP format
        Built on the packages sent back
        """
        s = 'T' + str(number) + '('
        
        if packet_received:
            s += 'R=Y%'
            
            ip_part = packet_received[IP]

            if 'DF' in ip_part.flags:
                s += 'DF=Y%'
            else:
                s += 'DF=N%'

            s += 'TG=' + hex(self.guess_ttl(ip_part.ttl))[2:].upper() + '%'

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
            s_options.create_options_from_packet(tcp_part.options)
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