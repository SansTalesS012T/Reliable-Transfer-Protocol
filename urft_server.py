import urft_system
import sys

BUFFSIZE = 65565
NETWORK_INTERFACE = (sys.argv[1], 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

while(True):
    res = control.listen()
    if(not res[0]):
        print("Connection Failed")
        continue
    print(f"Connection Successful with {res[1]}")
    control.save(control.recv_file())
    print("Saved!")
    break