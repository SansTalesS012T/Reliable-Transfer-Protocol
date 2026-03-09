from socket import *
import urft_system
import sys
import random
import time

BUFFSIZE = 65565
NETWORK_INTERFACE = (sys.argv[3], 0)

control = urft_system.RLTP(NETWORK_INTERFACE, BUFFSIZE)

connected = False

while(not connected):
    start = time.time()
    connected = control.connect((sys.argv[2]))
    if(connected[0]):
        print(f"Connection Successful with {sys.argv[2]}")
        control.send_file(sys.argv[1], (sys.argv[2], random.randint(5550, 10000)))
        print(f"Time use: {time.time() - start:.2f}")
    print("Done")