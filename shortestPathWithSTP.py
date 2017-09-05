'''
An L2 shortest path routing implementation in Ryu.
'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin, haddr_bitand, haddr_to_str
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx

class ShortestPathWithSTP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShortestPathWithSTP, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.mac_to_port = {}
        self.mcast_mask = '\x01\x00\x00\x00\x00\x00'
        self.paths = {} # a dict that will have a list of paths to each dst

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        elif idle_timeout:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # log packet if dst is not IPv6 multicast
        if dst[0:6] != "33:33:":
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port
            if haddr_bitand(haddr_to_bin(dst), self.mcast_mask) == self.mcast_mask:
                print("block 1")
                #if this is the first time receiving a packet from the source and it's a
                #multicast/broadcast, add a flow with high priority to flood multicast
                #traffic from the src on this port
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                mask = haddr_to_str(self.mcast_mask)
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=(mask, mask))
                self.add_flow(datapath, 1024, match, actions)

        if src in self.mac_to_port[dpid] and self.mac_to_port[dpid][src] != in_port:
            if haddr_bitand(haddr_to_bin(dst), self.mcast_mask) == self.mcast_mask:
                #add flow to block multicast traffic on this port to prevent network loops
                actions = [];
                #using a tuple for eth_dst creates a masked match field for dst
                mask = haddr_to_str(self.mcast_mask)
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=(mask, mask))
                self.add_flow(datapath, 4, match, actions)

        # update graph if needed
        if src not in self.net:
            self.net.add_node(src)
            # self.net is a directed graph, so two links are needed
            self.net.add_edge(dpid, src, {'port':in_port})
            self.net.add_edge(src, dpid)

        out_port = ofproto.OFPP_FLOOD   #default
        #check if there's already a path to this dest with this dp in it
        if dst in self.paths:
            for dest, pathList in self.paths.items():
                for path in pathList:
                    if dpid in path and path[-1] == dst:
                        nextHop = path[path.index(dpid) + 1]
                        out_port = self.net[dpid][nextHop]['port']
                        print("found pre-computed path from %s to %s" \
                                 %(src, dst))
                        print("dpid = %s, NH = %s, out_port = %s" %(dpid, nextHop, out_port))
                        print("path = %s" % str(path))
                        break

        #else, if dest is in the graph compute the shortest path
        elif dst in self.net:
            # try routing. if no route found, flood it
            try:
                path = nx.shortest_path(self.net, dpid, dst)
                nextHop = path[path.index(dpid) + 1]
                out_port = self.net[dpid][nextHop]['port']
                self.logger.info("path found from %s to %s. path = %s", \
                        dpid, dst, ''.join(str(foo)+' ' for foo in path))
                #add this path to the paths dict
                self.paths.setdefault(dst, [])
                self.paths[dst].append(path)

            except nx.NetworkXNoPath:
                self.logger.info("no path found from %s to %s. flooding", \
                        src, dst)
                out_port = ofproto.OFPP_FLOOD
        else:   #no route found. flood the packet
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time (if not flooding)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port':link.src.port_no})
                for link in links_list]

        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)

        # print graph for reference
        print("graph:")
        for (u, v, p) in self.net.edges(data='port'):
            if p:
                print(u, v, p)
            else:
                print(u, v)
    # remember to use --observe-links in command line for topology features
    # launch mininet with sudo mn --custom <topoFile> --topo <topo> --controller remote --switch ovsk,protocols=OpenFlow13
