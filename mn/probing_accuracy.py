'''Launches an experiment that probes the hard and idle timeouts.
It expects arguments on the commandline. It accepts [probe|experiment].
If probe is passed in, you should pass in the attacker's IP and the server's
IP address.

(c) 2021 Sohum Mendon
'''

import csv
import importlib
import sys
import time

import probe
import ryu
topology = importlib.import_module('topo-2sw-3host')

from mininet.node import Ryu, OVSSwitch
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

PROGRAM_FILE = '/home/mininet/rigel-sdn-dos/mn/probing_accuracy.py'


def probe_test():
    '''This method configures Mininet and launches the probe.'''

    # configure mininet instance
    topo = topology.TestbedTopo()
    args = 'ryu.app.ofctl_rest /home/mininet/rigel-sdn-dos/mn/simple_switch_14.py'
    net = Mininet(
        topo, 
        controller = lambda name: Ryu( 'c0' , args)
    )
    net.start()
    net.waitConnected()

    # print debugging information
    dumpNodeConnections(net.hosts)

    # extract the relevant hosts
    attacker = net.get( 'ah' )
    server = net.get( 'sh' )

    # run the probing code on the attacker
    result = attacker.cmd('python3 {} probe {} {}'.format(PROGRAM_FILE, attacker.IP(), server.IP()))
    print(result)

    # shutdown
    net.stop()


def launch_attack():
    '''This code collects arguments passed on the commandline and probes timeouts.'''
    prober = probe.Probing()

    # get the IP addresses from the command line
    src = sys.argv[2]
    dst = sys.argv[3]

    # launch the probing code
    hard_timeout = prober.mac_hard_timeout_probing(src=src, dst=dst)
    print('Hard timeout: {}'.format(hard_timeout))
    t_sup = hard_timeout if hard_timeout > 0 else 60  # if hard timeout = 0, we did not detect a hard timeout
    time.sleep(t_sup)  # flush the hard timeout
    idle_timeout = prober.mac_idle_timeout_probing(src=src, dst=dst, t_sup=t_sup)
    print('Idle timeout: {}'.format(idle_timeout))

    # append the result in mininet's home directory
    # with a timestamp
    with open('/home/mininet/results.csv', 'a+', newline='') as fp:
        writer = csv.writer(fp, delimiter=',')
        writer.writerow((time.ctime(), hard_timeout, idle_timeout))


if __name__ == '__main__':
    setLogLevel('info')  # configure the information mininet returns to us

    # error handling of invalid arguments
    if len(sys.argv) < 2 or sys.argv[1] not in ['experiment', 'probe']:
        print('usage: {} [experiment|probe]'.format(sys.argv[0]))
        sys.exit(-1)

    if sys.argv[1] == 'experiment':
        probe_test()
    else:
        if len(sys.argv) < 4:
            print('usage: {} probe <attacker ip> <server ip>'.format(sys.argv[0]))
            sys.exit(-1)
        launch_attack()
