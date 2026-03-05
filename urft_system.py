from socket import *
from random import *
import struct
import time
import threading

class PacketService:
    def __init__(self, packet = None):
        self.packet = packet
        self.TCP_HEADER_FORMAT = "!IIHB"
        self.IPV4_PROTOCOL = 0x0800
        self.UDP_PROTOCOL = 17

    def get_packet(self):
        return Packet(self.get_ethernet_header(), self.get_ip_header(), self.get_udp_header())

    def get_ethernet_header(self):
        return Ethernet(self.packet[:14])

    def get_ip_packet(self):
        return self.packet[14:34]

    def get_ip_header(self):
        return IPv4(self.get_ip_packet())

    def get_udp_packet(self):
        return self.packet[34:]

    def get_udp_header(self):
        return UDP(self.get_udp_packet())

    def pack_tcp(self, tcp):
        flag = (tcp.ack << 2) | (tcp.syn << 1) | tcp.fin
        res = struct.pack(self.TCP_HEADER_FORMAT, tcp.seq_num, tcp.ack_num, tcp.window_size, flag)
        if(tcp.data == None): return res
        return res + tcp.data

    def unpack_tcp(self, bytes):
        length = len(bytes) - 11
        lst = list(struct.unpack(self.TCP_HEADER_FORMAT + f"{length}s", bytes))
        data = lst.pop()
        flag = lst.pop()
        lst.extend([(flag & 0b100) >> 2, (flag & 0b010) >> 1, flag & 0b001, data])
        return TCP(*lst)
    
    def unpack_app(self, bytes):
        file_name = bytes[:20].decode().strip()
        content = bytes[20:]
        return (file_name, content)

    def validate_checksum(self, sub_packet):
        def end_around_carry(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        sum = 0
        for i in range(len(sub_packet), 2):
            cur = (int(sub_packet[i], 16) << 8) + int(sub_packet[i + 1], 16)
            sum = end_around_carry(sum, cur)

        return ~sum & 0xffff

    def is_packet_corrupted(self):
        return (self.validate_checksum(self.get_ip_packet()) & self.validate_checksum(self.get_udp_packet())) != 0xffff

class Packet:
    def __init__(self, ethernet, ipv4, udp):
        self.ethernet = ethernet
        self.ipv4 = ipv4
        self.udp = udp

class Ethernet:
    def __init__(self, ethernet_packet):
        self.src_mac = ethernet_packet[6:12]
        self.dst_mac = ethernet_packet[:6]
        self.protocol = int.from_bytes(ethernet_packet[12:14], "big")

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

class TCP:
    def __init__(self, seq_num, ack_num, window_size, ack, syn, fin, data):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.ack = ack
        self.syn = syn
        self.fin = fin
        self.data = data

class RLTP:
    def __init__(self, interface, buffsize):
        self.sl = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003)) # server listen socket
        self.sl.bind(interface)
        self.buffsize = buffsize
        self.ss = socket(AF_INET, SOCK_DGRAM)
        self.PS = PacketService()
        self.sender_history = list()
        self.thread = list()
        self.windows = 1400
        self.buffer = list()
        self.target_addr_port = None

        # for control tcp transmit
        self.last_transmit = 0
        self.transmit_complete = False
        self.quota = 0
        self.retransmit = False
        self.mss = 256


    def send_file(self, file_name, addr_port):
        if(len(file_name) > 20): 
            return 
        f = open(file_name, 'rb')
        raw = f"{file_name:<20}".encode() + f.read()
        bytes = [raw[i: i+self.windows if (i+self.windows < len(raw)) else len(raw)] for i in range(0, len(raw), self.windows)]
        tcps = self.prep_to_tcps(bytes)
        f.close()
        # print(f"Length: {len(tcps)}")
        t = threading.Thread(target = self.recv_ack, kwargs = {"tcps": tcps})
        t.start()
        cur_transmit = 0
        self.quota = self.mss
        while(cur_transmit < len(tcps)):
            # print(cur_transmit, self.quota, len(tcps))
            if(self.retransmit):
                print("retransmit!")
                self.quota = self.mss
                cur_transmit = self.last_transmit
                self.retransmit = False
            if(self.quota > 0):
                self.send(self.PS.pack_tcp(tcps[cur_transmit]), addr_port)
                # print("send!")
                cur_transmit += 1
                self.quota -= 1
        self.transmit_complete = True
        t.join()
        self.set_default_transmit_control()

    def send(self, bytes, addr_port):
        self.ss.sendto(bytes, addr_port)

    def recv(self):
        self.PS.packet = self.sl.recvfrom(self.buffsize)[0]
        res = self.PS.get_packet()
        # self.sender_history.append((res.ipv4.src_ip, res.udp.src_port))
        return res

    def recv_file(self, src_ip):
        complete = False
        ack = None
        bytes = b''
        while(not complete):
            packet = self.recv()

            if(self.PS.is_packet_corrupted() or
                packet.ethernet.protocol != self.PS.IPV4_PROTOCOL or 
                packet.ipv4.protocol != self.PS.UDP_PROTOCOL or
                src_ip != packet.ipv4.src_ip):
                self.send(self.PS.pack_tcp(TCP(0, ack, self.windows, 1, 0, 0, None)), 
                          (packet.ipv4.src_ip, packet.udp.src_port))
                self.clear()
                continue

            tcp_header = self.PS.unpack_tcp(packet.udp.data)
            bytes += tcp_header.data
            ack = ack + len(tcp_header.data) if ack != None else tcp_header.seq_num + len(tcp_header.data)
            self.send(self.PS.pack_tcp(0, ack, self.windows, 1, 0, 0, None))
            if(tcp_header.fin == 1):
                complete = True
        return bytes


    def recv_ack(self, tcps):
        last_time = time.time()
        i = 0
        count_dup = 0
        last_tcp = None
        need_ack = len(tcps[i].data)
        while(not self.transmit_complete):
            if(self.is_time_out(last_time, 50) or count_dup == 3):
                self.retransmit = True
                last_time = time.time()
                count_dup = 0
                continue

            packet = self.recv()

            if(self.PS.is_packet_corrupted() or
                packet.ethernet.protocol != self.PS.IPV4_PROTOCOL or 
                packet.ipv4.protocol != self.PS.UDP_PROTOCOL or
                self.target_addr_port[0] != packet.ipv4.src_ip):
                self.clear()
                continue

            tcp_header = self.PS.unpack_tcp(packet.udp.data)

            if(last_tcp != None and tcp_header.ack_num == last_tcp.ack_num):
                count_dup += 1
                continue

            if(last_tcp != None and tcp_header.ack_num == need_ack):
                self.quota += 1
                i += 1
                need_ack += len(tcps[i].data)
                count_dup = 0
                self.last_transmit += 1

            if(last_tcp != None and tcp_header.ack_num > need_ack):
                diff = tcp_header.ack_num - need_ack
                j = i
                while(j < len(tcps) and diff > 0):
                    diff -= len(tcps[j].data)
                    j += 1
                self.quota = self.mss
                i = j
                need_ack += len(tcps[i].data)
                self.last_transmit = i

            last_time = time.time()
            last_tcp = tcp_header
        print("Done Recv ACK")
            

    def connect(self, dst_ip):
        addr_port = (dst_ip, randint(5550, 10000))
        self.target_addr_port = addr_port
        # send syn
        self.send(self.PS.pack_tcp(TCP(1, 0, 64, 0, 1, 0, None)), addr_port)
        # wait for syn-ack
        last_time = time.time()
        syn_acked = False
        while(not syn_acked and not self.is_time_out(last_time, 50)):
            packet = self.recv()
            if(self.PS.is_packet_corrupted() or 
               packet.ethernet.protocol != self.PS.IPV4_PROTOCOL or 
               packet.ipv4.protocol != self.PS.UDP_PROTOCOL or
               packet.ipv4.src_ip != dst_ip):
                self.clear()
                continue
            tcp_header = self.PS.unpack_tcp(packet.udp.data)
            if((tcp_header.seq_num == 1 and tcp_header.ack_num == 1) and 
               (tcp_header.syn == 1 and tcp_header.ack == 1)):
                syn_acked = True

        self.clear()
        if(not syn_acked):
            return False, "TIMEOUT"

        # send ack
        self.send(self.PS.pack_tcp(TCP(2, 1, 64, 1, 0, 0, None)), addr_port)

        return True, "OK"

    def prep_to_tcps(self, file_bytes):
        cur_size = 0
        res = list()
        for i, byte in enumerate(file_bytes):
            res.append(TCP(cur_size, 0, self.windows, 1, 0, 0 if i + 1 != len(file_bytes) else 1, byte))
            cur_size += len(byte)
        return res

    def accept(self, addr_port):
        # send syn-ack
        self.send(self.PS.pack_tcp(TCP(1, 1, 64, 1, 1, 0, None)), addr_port)
        # wait for ack
        acked = False
        last_time = time.time()
        res = None
        while(not acked and not self.is_time_out(last_time, 50)):
            packet = self.recv()
            if(self.PS.is_packet_corrupted() or 
               packet.ethernet.protocol != self.PS.IPV4_PROTOCOL or 
               packet.ipv4.protocol != self.PS.UDP_PROTOCOL):
                self.clear()
                continue

            tcp_header = self.PS.unpack_tcp(packet.udp.data)

            if((tcp_header.seq_num == 2 and tcp_header.ack_num == 1) and 
               (tcp_header.ack)):
                acked = True
                res = (packet.ipv4.src_ip, packet.udp.src_port, tcp_header.data)
                self.windows = tcp_header.window_size

        self.clear()
        if(not acked):
            return False, res

        return True, res
    
    def save(self, bytes):
        file_name, content = self.PS.unpack_app(bytes)
        f = open(file_name, 'wb')
        f.write(content)
        f.close()

    def listen(self):
        connected = False
        res = None
        while(not connected):
            packet = self.recv()
            if(packet.ethernet.protocol != self.PS.IPV4_PROTOCOL or
            packet.ipv4.protocol != self.PS.UDP_PROTOCOL or
            self.PS.is_packet_corrupted()):
                self.clear()
                continue

            tcp_header = self.PS.unpack_tcp(packet.udp.data)
        
            if(tcp_header.syn != 1 or tcp_header.seq_num != 1 or tcp_header.ack_num != 0):
                self.clear()
                continue

            connected, res = self.accept((packet.ipv4.src_ip, packet.udp.src_port))
        return res

    def is_time_out(self, ref, limit):
        return (time.time() - ref)*1000 >= limit

    def clear(self):
        self.PS.packet = None
        self.sender_history.clear()

    def set_default_transmit_control(self):
        self.last_transmit = 0
        self.transmit_complete = False
        self.quota = 0
        self.retransmit = False