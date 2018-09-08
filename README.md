README

This project is my work with Professor Brad Smith at the University of 
California at Santa Cruz to develop a "partially-ordered Internet" using 
Dominant Set Multipath Routing (DSMR), Software-Defined Networking (SDN), and
Multiprotocol Label-Switching (MPLS).


to launch the controller:
    `$ ryu-manager controllerFile.py --observe-links`

to launch Mininet:
    `$ sudo mn --controller remote --custom TopoFile.py --topo TopoName --switch
ovs,protocols=OpenFlow13 --link=tc`

