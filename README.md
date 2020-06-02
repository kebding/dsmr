README

This project is my work with Professor 
[Brad Smith](https://users.soe.ucsc.edu/~brad/) at the University of 
California at Santa Cruz to develop a "partially-ordered Internet" using 
Dominant Set Multipath Routing (DSMR), Software-Defined Networking (SDN), and
Multiprotocol Label-Switching (MPLS). This project is being used as my
Master's project.

The project uses the [Ryu SDN controller](https://osrg.github.io/ryu/) and 
runs in the [mininet](http://mininet.org/) virtual network tool.

Note: after launching Mininet, the user must set the host's interfaces' MTU to
be at least 4 bytes fewer than the switches' MTU (default 1500). This is
because adding an MPLS header to a packet adds 4 bytes of data.

to launch the controller:
    `$ ryu-manager controllerFile.py --observe-links`

to launch Mininet using the provided custom topology:
    `$ sudo mn --controller remote --custom TopoFile.py --topo TopoName --switch
ovs,protocols=OpenFlow13 --link=tc`

to view flows on a switch:
    `sudo ovs-ofctl -O OpenFlow13 dump-flows <switch name>`
