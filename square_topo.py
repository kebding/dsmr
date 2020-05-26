#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import TCLink, Intf

''' 
launches a custom square topology that will have two routes from s1 to s3 when
using multipath_dijkstra due to the differences in bandwidth across the links
# launch mininet with sudo mn --custom <topoFile> --topo <topo> --controller remote --switch ovsk,protocols=OpenFlow13 --link=tc
'''
class square_topo(Topo):
  def build(self):
    # create the hosts and switches
    s1 = self.addSwitch('s1')
    s2 = self.addSwitch('s2')
    s3 = self.addSwitch('s3')
    s4 = self.addSwitch('s4')
    h1 = self.addHost('h1',mac='00:00:00:00:00:01',ip='10.0.0.1/24')
    h2 = self.addHost('h2',mac='00:00:00:00:00:02',ip='10.0.0.2/24')
    h3 = self.addHost('h3',mac='00:00:00:00:00:03',ip='10.0.0.3/24')
    h4 = self.addHost('h4',mac='00:00:00:00:00:04',ip='10.0.0.4/24')

    # create the host-to-switch links
    self.addLink(h1,s1)
    self.addLink(h2,s2)
    self.addLink(h3,s3)
    self.addLink(h4,s4)

    # create the switch-to-switch links
    self.addLink(s1, s2, bw=30)
    self.addLink(s1, s3, bw=10)
    self.addLink(s3, s4, bw=15)
    self.addLink(s2, s4, bw=12)

def configure():
  topo = square_topo()
  net = Mininet(topo=topo, controller=RemoteController)
  net.start()
  h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
  
  CLI(net)

  net.stop()


if __name__ == '__main__':
  configure()

topos = {'square_topo': (lambda: square_topo() )}
