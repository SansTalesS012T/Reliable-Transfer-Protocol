from socket import *

BUFFSIZE = 65565
SERVER_ADDR_PORT = ("25.57.104.211", 10000)

client_socket = socket(AF_INET, SOCK_DGRAM)

client_socket.sendto("Hello World!".encode(), SERVER_ADDR_PORT)

# packet, addr = client_socket.recvfrom(BUFFSIZE)

# print(f"Server response {packet.decode()} from {addr}")