from socket import *
import urft_system

BUFFSIZE = 65565
NETWORK_INTERFACE = ("wlp3s0", 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

while(True):
    res = control.listen()
    if(not res[0]):
        print("Connection Failed")
        continue
    print(res[1])
    control.save(control.recv_file(res[1][0]))
    print("Saved!")