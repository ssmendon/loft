#!/bin/bash
import sys
import os
import time
from scapy.all import*

def scapyGen():
    x = []
    for i in range(25):
        src_mac = RandMAC()
        src = '10.0.0.1'
        dst = '10.0.0.3'
        x.append((Ether(src=src_mac, dst = "00:00:00:00:00:03")/IP(src = src, dst = dst)/ICMP(id=RandShort())))
    while 1:
        print("Sending 25 benign network flows")
        sendpfast(x)
        time.sleep(5)
 
scapyGen()
