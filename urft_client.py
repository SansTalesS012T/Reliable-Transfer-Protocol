from socket import *

BUFFSIZE = 65565
SERVER_ADDR_PORT = ("172.20.10.2", 5553)

client_socket = socket(AF_INET, SOCK_DGRAM)
client_socket.bind(SERVER_ADDR_PORT)

client_socket.sendto("Hello World!".encode(), SERVER_ADDR_PORT)
packet, addr = client_socket.recvfrom(BUFFSIZE)

print(f"Server response {packet.decode()} from {addr}")