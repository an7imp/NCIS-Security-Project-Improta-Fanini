#!/usr/bin/python
from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink


class Environment(object):

    def __init__(self):
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)
        c1.start()

        info("*** Adding hosts\n")
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')
        self.a1 = self.net.addHost('a1', mac='00:00:00:00:00:A1', ip='10.0.0.101/24')
        self.a2 = self.net.addHost('a2', mac='00:00:00:00:00:A2', ip='10.0.0.102/24')

        info("*** Adding 10 switches\n")
        self.switches = {}
        for idx in range(1, 11):
            name = f's{idx}'
            self.switches[name] = self.net.addSwitch(name, cls=OVSKernelSwitch)

        info("*** Adding host access links\n")
        self.net.addLink(self.h1, self.switches['s1'], bw=10, delay='0.5ms')
        self.net.addLink(self.h2, self.switches['s2'], bw=10, delay='0.5ms')
        self.net.addLink(self.a1, self.switches['s9'], bw=10, delay='0.5ms')
        self.net.addLink(self.a2, self.switches['s10'], bw=10, delay='0.5ms')

        info("*** Adding switch fabric links\n")
        self.net.addLink(self.switches['s1'], self.switches['s3'], bw=6, delay='5ms')
        self.net.addLink(self.switches['s9'], self.switches['s3'], bw=6, delay='5ms')

        self.net.addLink(self.switches['s3'], self.switches['s5'], bw=7, delay='10ms')
        self.net.addLink(self.switches['s5'], self.switches['s7'], bw=7, delay='10ms')
        self.net.addLink(self.switches['s7'], self.switches['s6'], bw=7, delay='12ms')
        self.net.addLink(self.switches['s6'], self.switches['s8'], bw=7, delay='10ms')
        self.net.addLink(self.switches['s8'], self.switches['s4'], bw=7, delay='10ms')

        self.net.addLink(self.switches['s4'], self.switches['s2'], bw=10, delay='5ms')
        self.net.addLink(self.switches['s4'], self.switches['s10'], bw=6, delay='5ms')

        info("*** Topology summary\n")
        info("    Legitimate path: h1(s1) -> s3 -> s5 -> s7 -> s6 -> s8 -> s4 -> s2(h2)\n")
        info("    Attackers: a1 on s9 and a2 on s10 \n")
        info("    Shared bottleneck: links s7-s6 and core segment around s5/s6\n")

        info("*** Starting network\n")
        self.net.build()
        self.net.start()


if __name__ == '__main__':
    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)