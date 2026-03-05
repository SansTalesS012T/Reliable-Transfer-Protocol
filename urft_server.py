from socket import *
import urft_system

BUFFSIZE = 65565
NETWORK_INTERFACE = ("wlp3s0", 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

connected = False

while(not connected):
    packet = control.recv()

    if(packet.ethernet.protocol != control.PS.IPV4_PROTOCOL or 
       packet.ipv4.protocol != control.PS.UDP_PROTOCOL or
       control.PS.is_packet_corrupted()):
        control.clear()
        continue

    tcp_header = control.PS.unpack_tcp(packet.udp.data)

    if(tcp_header.syn != 1 or tcp_header.seq_num != 1 or tcp_header.ack_num != 0):
        control.clear()
        continue

    connected = control.accept((packet.ipv4.src_ip, packet.udp.src_port))

print("connected!")
    
# while True:
#     PS.packet, addr = server_socket.recvfrom(BUFFSIZE)
#     eth_header = PS.get_ethernet_header()
#     protocol = eth_header[2]

#     if(protocol != 0x0800 or PS.validate_checksum(PS.get_ip_packet()) != 0xffff): # check if It IPv4
#         continue

#     ip_header = PS.get_ip_header()
#     ip_packet = PS.get_ip_packet()
    
#     if(ip_header.protocol != 17 or PS.validate_checksum(PS.get_udp_packet()) != 0xffff): 
#         continue

#     udp_header = PS.get_udp_header()
#     if(udp_header.dst_port == 5553):
#         print(f"{udp_header.data.decode()} from {addr}")
#         server_send_socket.sendto("Acknowledge".encode(), (ip_header.src_ip, udp_header.src_port))
#         print(f"\n\nSending {"Acknowledge".encode()} to {(ip_header.src_ip, udp_header.src_port)}\n")