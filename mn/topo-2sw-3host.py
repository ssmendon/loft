"""Custom topology used in LOFT paper.

Two directly connected switches. One switch connects to a webserver,
and the other switch connects to two hosts (one is a webserver client,
the other is the attacker).

    client
              >  --- switch --- switch --- server
    attacker

Pass '--topo testbedtopo' to use.

See the following links for more resources:
- http://mininet.org/api/hierarchy.html
- http://mininet.org/walkthrough/#custom-topologies
- https://github.com/mininet/mininet/wiki/Mininet-Python-Style
- https://github.com/mininet/mininet/wiki/FAQ#python-api
"""

from mininet.topo import Topo
from mininet.node import OVSSwitch

class TestbedTopo( Topo ):

    def __init__( self ):

        Topo.__init__( self )

        client = self.addHost( 'ch')
        attacker = self.addHost( 'ah' )
        server = self.addHost( 'sh' )

        clientSwitch = self.addSwitch( 's4', cls = OVSSwitch, protocols='OpenFlow14' )
        serverSwitch = self.addSwitch( 's5', cls = OVSSwitch, protocols='OpenFlow14' )

        self.addLink(client, clientSwitch)
        self.addLink(attacker, clientSwitch)

        self.addLink(clientSwitch, serverSwitch)

        self.addLink(serverSwitch, server)

topos = { 'testbedtopo': ( lambda: TestbedTopo() ) }
