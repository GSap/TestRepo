"""Custom topology

4 connected switches plus a host for each switch:

   host --- switch --- switch --- host
		|	|
		|	|
   host --- switch --- switch --- host

"""
#!/usr/bin/python

from mininet.topo import Topo
from mininet.node import *
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.log import setLogLevel

def Test():
    #"Create network and run simple test" or switch=OVSSwitch

    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink) # autoStaticArp=True

    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    # Switches
    s5 = net.addSwitch('s5')
    s6 = net.addSwitch('s6')
    s7 = net.addSwitch('s7')
    s8 = net.addSwitch('s8')

    # Hosts
    h1 = net.addHost('h1', ip="192.168.1.1/24")
    h2 = net.addHost('h2', ip="192.168.2.1/24")
    h3 = net.addHost('h3', ip="192.168.3.1/24")
    h4 = net.addHost('h4', ip="192.168.4.1/24")

    # Host-Switch Links
    # 1000 Mbps, 0ms delay, 0% loss, 1000 packet queue
    net.addLink(h1, s5, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(h2, s6, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(h3, s7, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(h4, s8, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)

    # Switch-Switch Links
    # 1000 Mbps, 0ms delay, 0% loss, 1000 packet queue
    net.addLink(s5, s6, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(s5, s7, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(s7, s8, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(s6, s8, bw=80, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)

    print "\nConfiguring MAC addresses and Default gateways"
    h1,h2,h3,h4 = net.get('h1','h2','h3','h4')

    # h1.setIP("192.168.1.1", 24, "h1-eth0") # this does not work when at this point
    h1.setMAC("00:00:00:00:00:01", "h1-eth0")
    h1.setDefaultRoute("h1-eth0")

    # h2.setIP("192.168.2.1", 24, "h2-eth0")
    h2.setMAC("00:00:00:00:00:02", "h2-eth0")
    h2.setDefaultRoute("h2-eth0")

    # h3.setIP("192.168.3.1", 24, "h3-eth0")
    h3.setMAC("00:00:00:00:00:03", "h3-eth0")
    h3.setDefaultRoute("h3-eth0")

    # h4.setIP("192.168.4.1", 24, "h4-eth0")
    h4.setMAC("00:00:00:00:00:04", "h4-eth0")
    h4.setDefaultRoute("h4-eth0")

    # net.staticArp()
    net.start()
    print "\nInstalling ARP entries"

    h1.setARP("192.168.2.1", "00:00:00:00:00:02")
    h1.setARP("192.168.3.1", "00:00:00:00:00:03")
    h1.setARP("192.168.4.1", "00:00:00:00:00:04")
    # or
    # h1.cmd('arp -s 192.168.2.1 00:00:00:00:00:02')
    # h1.cmd('arp -s 192.168.3.1 00:00:00:00:00:03')
    # h1.cmd('arp -s 192.168.4.1 00:00:00:00:00:04')

    h2.setARP("192.168.1.1", "00:00:00:00:00:01")
    h2.setARP("192.168.3.1", "00:00:00:00:00:03")
    h2.setARP("192.168.4.1", "00:00:00:00:00:04")

    h3.setARP("192.168.1.1", "00:00:00:00:00:01")
    h3.setARP("192.168.2.1", "00:00:00:00:00:02")
    h3.setARP("192.168.4.1", "00:00:00:00:00:04")

    h4.setARP("192.168.1.1", "00:00:00:00:00:01")
    h4.setARP("192.168.2.1", "00:00:00:00:00:02")
    h4.setARP("192.168.3.1", "00:00:00:00:00:03")

    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    Test()

