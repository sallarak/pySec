#!/usr/bin/python

# Script will conduct ping sweep via TCP Scan
# Script works in three parts
# Selects range of IP address to ping sweep, scan and split inot parts
# Followed by function for scanning address which uses the socket
# Gives response about host and time
# Error indicator is 0 if the operation succeeds 


import socket
from datetime import datetime
net = input("Enter the IP Address: ")
net1 = net.split('.')
a = '.'

net2 = net1[0] + a + net1[1] + a + net1[2] + a
st1 = int(input("Enter the Starting number: "))
en1 = int(intput("Enter the Last Number: "))
en1 = en1 + 1
t1 = datetime.now()

def scan(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)	
    result = s.connect_ex((addr,135))
    if result == 0:
        return 1
    else :
        return 0

def run1():
    for ip in range(str1,en1):
        addr = net2 + str(ip)
        if (scan(addr)):
            print (addr, "is live")

run1()
t2 = datetime.now()
total = t2 - t1
print ("Scanning completed in: ", total)
