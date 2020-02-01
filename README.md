README

This project is my work with Professor Brad Smith at the University of 
California at Santa Cruz to develop a "partially-ordered Internet" using 
Dominant Set Multipath Routing (DSMR), Software-Defined Networking (SDN), and
Multiprotocol Label-Switching (MPLS).

This is a work-in-progress, and will likely become my Master's project.

The project uses the [Ryu SDN controller](https://osrg.github.io/ryu/) and runs in the [mininet](http://mininet.org/) virtual network tool.


to launch the controller:
    `$ ryu-manager controllerFile.py --observe-links`

to launch Mininet:
    `$ sudo mn --controller remote --custom TopoFile.py --topo TopoName --switch
ovs,protocols=OpenFlow13 --link=tc`

to view flows on a switch:
    `sudo ovs-ofctl -O OpenFlow13 dump-flows switchName`
