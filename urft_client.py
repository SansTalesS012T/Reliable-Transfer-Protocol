from socket import *
import urft_system
import sys
import random

BUFFSIZE = 65565
NETWORK_INTERFACE = ("wlp3s0", 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

connected = False

while(not connected):
    connected = control.connect((sys.argv[1]), random.randint(5553, 10000))
    
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