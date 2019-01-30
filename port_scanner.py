#!/usr/bin/python

#Python script for port scanning using socket
# Tutorials Point

from socket import *
import time
startTime = time.time()

if __name__ == '__main__':
    target = input('Enter the host to be scanned: ')
    t_IP = gethostbyname(target)
    print ('Starting scan on host: ', t_IP)

for i in range(50, 500):
    s = scoket(AF_INET, SOCET_STREAM)
    
    conn = s.connect_ex((t_IP, i))
    if(conn == 0) :
        print ('Port %d: OPEN' % (i,))
    s.cole()
print('Time Taken:', time.time() - startTime)
