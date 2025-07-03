from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel

class LACPTopo(Topo):
    def build(self):
        # Create switch
        switch = self.addSwitch('s1')

        # Create web server host (h1) with 4 links
        web_host = self.addHost('h1')
        for link_num in range(1, 5):
            self.addLink(web_host, switch, cls=TCLink,
                        bw=10, delay='1ms', loss=0, r2q=1000,
                        intfName1=f'h1-eth{link_num}',
                        intfName2=f's1-eth{link_num}')

        # Create 3 client hosts (h2 to h4) with 1 link each
        for k in range(2, 5):
            host_obj = self.addHost(f'h{k}')
            self.addLink(host_obj, switch, cls=TCLink,
                        bw=10, delay='1ms', loss=0, r2q=1000,
                        intfName1=f'h{k}-eth0',
                        intfName2=f's1-eth{4 + k-1}')
topos = {'lacptopo': LACPTopo}

def run_topology():
    setLogLevel('debug')  # Enable debug logging
    topo = LACPTopo()
    net = Mininet(topo=topo, link=TCLink, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653), switch=OVSSwitch)
    
    # Start the network
    net.start()

    # Configure IP addresses
    h1 = net.get('h1')
    for i in range(1, 5):
        h1.setIP(f'10.0.0.1', intf=f'h1-eth{i}')  # Set same IP for all h1 interfaces
    for i in range(2, 5):
        host = net.get(f'h{i}')
        host.setIP(f'10.0.0.{i}', intf=f'h{i}-eth0')

    # Configure web server on h1
    h1.cmd('apt-get update && apt-get install -y nginx')
    h1.cmd('service nginx start')
    print("Web server started on h1, accessible at 10.0.0.1:80")

    # Verify controller connection
    for switch in net.switches:
        switch.cmd('ovs-vsctl set-controller {} tcp:127.0.0.1:6653'.format(switch.name))
        print(f"Set controller for {switch.name} to tcp:127.0.0.1:6653")

    # Test connectivity
    print("Running pingAll to test connectivity...")
    net.pingAll()

    # Instructions for testing web server
    print("To test web server access, from h2-h4 CLI, run: curl http://10.0.0.1")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run_topology()
