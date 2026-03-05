from socket import *
import urft_system

BUFFSIZE = 65565
NETWORK_INTERFACE = ("wlp3s0", 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

while(True):
    res = control.listen()
    control.save(control.recv_file(res[0]))
    print("Saved!")