import attack
import probe
import sys
import os


def runIdleOnly():
    packet_length = 1
    maxCount = 1000
    
    print("creating probe instance")
    probeI = probe.Probing()
    
    print("finding idle timeout")
    idle_timeout = probeI.mac_idle_timeout_probing(t_sup = 60)
    
    print("Calculating attack catagory")
    attackC = attack.min_attack_rate_category(0, idle_timeout)
    if attackC == 3:
        print("Commencing catagory 3 attack")
        attack.catagory_three_attack(packet_length, maxCount, idle_timeout)
    elif attackC == 4:
        print("Commencing catagory 4 attack")
        attack.catagory_four_attack(packet_length, maxCount, idle_timeout, 0)
    else:
        print("Error, invalid attack catagory")

def runIdleANDHard():
    packet_length = 1
    maxCount = 1000

    print("Creating probe instance")
    probeI = probe.Probing()

    print("Finding hard timeout")
    hard_timeout = probeI.mac_hard_timeout_probing()
    print("Finding idle timeout")
    idle_timeout = probeI.mac_idle_timeout_probing(t_sup = hard_timeout)
    
    print("Calculating attack catagory")
    attackC = attack.min_attack_rate_category(hard_timeout, idle_timeout)
    if attackC == 3:
        print("Commencing catagory 3 attack")
        attack.catagory_three_attack(packet_length, maxCount, idle_timeout)
    elif attackC == 4:
        print("Commencing catagory 4 attack")
        attack.catagory_four_attack(packet_length, maxCount, idle_timeout, hard_timeout)
    else:
        print("Error, invalid attack catagory")

if __name__ == '__main__':
    # added by Sohum
    # automates whether or not we are doing hard vs. idle timeout approaches
    packet_length, max_count = 1, 1000
    prober = probe.Probing()

    print('Finding hard timeout')
    hard_timeout = prober.mac_hard_timeout_probing()
    print('Hard timeout = {}'.format(hard_timeout))

    t_sup = hard_timeout if hard_timeout > 0 else 60

    print('Finding idle timeout')
    idle_timeout = prober.mac_idle_timeout_probing(t_sup=t_sup)
    print('Idle timeout = {}'.format(idle_timeout))

    attack_category = attack.min_attack_rate_category(hard_timeout, idle_timeout)
    print('Attack category {}'.format(attack_category))
    if attack_category == 3:
        attack.catagory_three_attack(packet_length, max_count, idle_timeout)
    elif attack_category == 4:
        attack.catagory_four_attack(packet_length, max_count, idle_timeout, hard_timeout)
    else:
        print('ERROR: invalid attack category {}'.format(attack_category))


#runIdleOnly()
#runIdleANDHard()
