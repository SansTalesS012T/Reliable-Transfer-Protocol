from socket import *
import struct

class PacketService:
    def __init__(self):
        pass

    def get_ethernet_header(self, packet):
        return struct.unpack("!6s6sH", packet[:14])
    
    def get_ip_packet(self, packet):
        return packet[14:34]
    
    def get_ip_header(self, packet):
        return IPv4(self.get_ip_packet(packet))
        return struct.unpack("!BBHHHBBH4s4s", self.get_ip_packet(packet))

    def get_udp_packet(self, packet):
        return packet[34:]
    
    def get_udp_header(self, packet):
        return UDP(self.get_udp_packet(packet))

    def validate_checksum(self, sub_packet):
        def end_around_carry(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        sum = 0
        for i in range(len(sub_packet), 2):
            cur = (int(sub_packet[i], 16) << 8) + int(sub_packet[i + 1], 16)
            sum = end_around_carry(sum, cur)

        return ~sum & 0xffff

class IPv4:
    def __init__(self, ipv4_packet):
        self.version =  ((ipv4_packet[0]) >> 4) & 0xf
        self.header = (ipv4_packet[0]) & 0xf
        self.diff_service = None
        self.tot_length = int.from_bytes(ipv4_packet[2:4], "big")
        self.iden = int.from_bytes(ipv4_packet[4:6], "big")
        self.flags =  ((ipv4_packet[6]) >> 5) & 0b111
        self.fragment_offset = (int.from_bytes(ipv4_packet[6:8], "big")) & 0x1fff
        self.ttl = (ipv4_packet[8])
        self.protocol = (ipv4_packet[9])
        self.checksum = int.from_bytes(ipv4_packet[10:12], "big")
        self.src_ip = ".".join(str(i) for i in ipv4_packet[12:16])
        self.dst_ip = ".".join(str(i) for i in ipv4_packet[16:20])

class UDP:
    def __init__(self, udp_packet):
        self.src_port = int.from_bytes(udp_packet[0:2], "big")
        self.dst_port = int.from_bytes(udp_packet[2:4], "big")
        self.length = int.from_bytes(udp_packet[4:6], "big")
        self.checksum = int.from_bytes(udp_packet[6:8], "big")
        self.data = udp_packet[8:]

class RLTP:
    def __init__(self):
        pass