from socket import *
import urft_system

BUFFSIZE = 65565
NETWORK_INTERFACE = ("wlp3s0", 0)

server_socket = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
server_socket.bind(NETWORK_INTERFACE)

server_send_socket = socket(AF_INET, SOCK_DGRAM)

PS = urft_system.PacketService()

while True:
    PS.packet, addr = server_socket.recvfrom(BUFFSIZE)
    eth_header = PS.get_ethernet_header()
    protocol = eth_header[2]

    if(protocol != 0x0800 or PS.validate_checksum(PS.get_ip_packet()) != 0xffff): # check if It IPv4
        continue

    ip_header = PS.get_ip_header()
    ip_packet = PS.get_ip_packet()
    
    if(ip_header.protocol != 17 or PS.validate_checksum(PS.get_udp_packet()) != 0xffff): 
        continue

    udp_header = PS.get_udp_header()
    if(udp_header.dst_port == 5553):
        print(f"{udp_header.data.decode()} from {addr}")
        server_send_socket.sendto("Acknowledge".encode(), (ip_header.src_ip, udp_header.src_port))
        print(f"\n\nSending {"Acknowledge".encode()} to {(ip_header.src_ip, udp_header.src_port)}\n")