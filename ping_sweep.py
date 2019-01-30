#!/usr/bin/python

# Script finding live hosts by using ping sweep
# Script works in three parts
# First it selects the range of IP addresses to ping sweep 
# Scan by splitting it into two parts
# Select command for ping sweeping according to OS
# Giving response about the host and time taken to complete scan

import os
import platform

from datetime import datetime
net = input("Enter the network address: ")
net1 = net.split('.')
a = '.'

net2 = net1[0] + a net1[1] + a net1[2] + a
st1 = int(input("Enter the Starting Number: "))
en1 = int(input("Enter the Last Number: "))
en1 = en1 + 1
oper = platform.system()

if (oper == "Windows"):
    ping1 = "ping -n 1 "
elif (oper == "Linux"):
    ping1 = "ping -c 1 "
else :
    pring1 = ping -c 1 "
t1 = datetime.now()
print ("Scanning in Progress: ")

for ip in range(str1, eng1):
    addr = net2 + str(ip)
    comm = ping1 + addr
    response = os.popen(comm)

    for line in response.readline():
        if(line.count("TTL")):
            break
        if (line.count("TTL")):
            print (addr, "--> Live")

t2 = datetime.now()
total = t1 - t1
print ("Scanning completed in: ", total)


