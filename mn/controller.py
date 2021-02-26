import ryu
import sys
import os
import json
import time

ryuI = ryu.RyuAPI("localhost:8080")
print("Made Ryu API instance")

def getDataMetrics():

    #Lists to hold flow rules
    flow_rulesS4 = []
    flow_rulesS5 = []
    
    while 1:
        print("Getting JSON Response")
        JSON_ResponseS4 = ryuI.aggregate_flow_stats(4)
        JSON_ResponseS5 = ryuI.aggregate_flow_stats(5)
    
        print(JSON_ResponseS4)
        print(JSON_ResponseS5)
        print(time.asctime(time.localtime(time.time())))

        print("Acquring flow count")
        flow_rulesS4.append(JSON_ResponseS4['4'][0]['flow_count'])
        flow_rulesS5.append( JSON_ResponseS5['5'][0]['flow_count'])
        time.sleep(5)

        print(flow_rulesS4)
        print(flow_rulesS5)

def changeSDNRuleCount():
    os.system("ovs-vsctl -- --id=@ft create Flow_Table flow_limit=100 overflow_policy=refuse -- set Bridge s4 flow_tables=0=@ft")
    os.system("ovs-vsctl -- --id=@ft create Flow_Table flow_limit=100 overflow_policy=refuse -- set Bridge s5 flow_tables=0=@ft")


changeSDNRuleCount()
print("Successfully changed rule count")

getDataMetrics()
