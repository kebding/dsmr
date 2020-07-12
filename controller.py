'''
An L2 shortest path routing implementation in Ryu.

use --observe-links in command line for topology features

launch mininet with sudo mn --custom <topoFile> --topo <topo> \
        --controller remote --switch ovsk,protocols=OpenFlow13 --link=tc
'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, mpls, in_proto, ipv4, tcp, udp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx
from routing_labels import compute_mpls_labels, print_mpls_labels
from time import sleep

class DsmrController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DsmrController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.default_table_id = 0
        self.mac_to_port = {} # will have key=dpid, val={host: dpid_port}
        self.mpls_dst_table_id = 1
        self.mpls_ttl = 16
        self.mcast_mask = '01:00:00:00:00:00'
        self.labels = {} # see multipath_labelSwap for info
        self.switch_ofprotos = {}
        self.switch_parsers = {}
        self.bw_ports = [5002]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # record the switch's ofproto for use later
        self.switch_ofprotos[datapath.id] = ofproto
        self.switch_parsers[datapath.id] = parser

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
        instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, instructions, self.default_table_id)
        self.add_flow(datapath, 0, match, instructions, self.mpls_dst_table_id)

    def print_graph(self):
        # print graph for reference
        print("graph:")
        for edge in self.net.edges():
            print(edge[0],edge[1],self.net[edge[0]][edge[1]])

    def print_labels(self):
        # print labels for reference
        print_mpls_labels(self.labels)

    def add_flow(self, datapath, priority, match, instructions, table_id=0,
            buffer_id=None, idle_timeout=None):
        #print("ADD FLOW")
        #print("datapath={}\npriority={}\nmatch={}\ninstructions={}\ntable_id={}\n".format(
        #    datapath.id, priority, match, instructions, table_id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    table_id=table_id, instructions=instructions)
        elif idle_timeout:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, table_id=table_id,
                                    instructions=instructions,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, table_id=table_id,
                                    instructions=instructions)
        datapath.send_msg(mod)

    # This function removes all flows from the default table, which contains
    # all flows except the mac-to-port mapping flows for the final hop of a path
    def remove_flows(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match_all = parser.OFPMatch()
        delete_flows_mod = parser.OFPFlowMod(datapath=datapath,
                table_id=self.default_table_id, match=match_all,
                command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(delete_flows_mod)
        # now re-add the table-miss flow entry
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match_all, instructions, self.default_table_id)


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

        # filter IPv6 broadcasts
        if dst[0:6] == "33:33:":
            return

        dpid = datapath.id

        # if this dp has not been seen before, add an entry
        self.mac_to_port.setdefault(dpid, {})

        # log packet
        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        self.logger.info("packet in: dpid=%s src=%s dst=%s in_port=%d " + \
                "ethertype=%s table_id=%d, reason=%s",
                dpid, src, dst, in_port, hex(eth.ethertype), msg.table_id, reason)

        if eth.ethertype == ether_types.ETH_TYPE_MPLS:
            packet_mpls = pkt.get_protocol(mpls.mpls)
            self.logger.info("mpls_label = %s, mpls_TTL = %s",
                    packet_mpls.label, packet_mpls.ttl)
        # if sent to controller just to log, return now
        if msg.reason == ofproto.OFPR_ACTION:
            return

        # if this is the first time receiving a packet from the source,
        # add it to the controller's view of the topology
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port
            # add a flow with medium priority to flood multicast traffic from
            # this src on this port
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            instructions = [parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # using a tuple for eth_dst creates a masked match field for dst
            match = parser.OFPMatch(in_port=in_port, eth_src=src,
                    eth_dst=(self.mcast_mask, self.mcast_mask))
            self.add_flow(datapath, 500, match, instructions,
                    self.default_table_id)

            # add flow to block multicast traffic on every port to prevent network loops
            # (this won't block the origin port because this has a lower priority match)
            blockActions = [];
            blockMatch = parser.OFPMatch(eth_src=src,
                    eth_dst=(self.mcast_mask, self.mcast_mask))
            self.add_flow(datapath, 8, blockMatch, blockActions,
                    self.default_table_id)
        if src not in self.net:
            self.net.add_node(src)
            # self.net is a directed graph, so two links are needed
            self.net.add_edges_from([(dpid, src, {'port':in_port}),
                                     (src, dpid)])
            # add these flows to forward packets to the host
            match = parser.OFPMatch(eth_dst=src)
            actions = [parser.OFPActionOutput(in_port)]
            instructions = [parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, 4, match, instructions,
                    self.default_table_id)
            self.add_flow(datapath, 4, match, instructions,
                    self.mpls_dst_table_id)

            # print graph for reference
            self.print_graph()

        out_port = ofproto.OFPP_FLOOD   # default
        table_id = self.default_table_id
        dst_switch = None
        msg_actions = None

        # handle broadcast messages
        if dst == "ff:ff:ff:ff:ff:ff":
            msg_actions = [parser.OFPActionOutput(out_port)]

        # handle cases of unicast messages new to the network
        elif eth.ethertype != ether_types.ETH_TYPE_MPLS:
            # get the switch connected to dst.
            # assumes hosts each have only 1 link and that it is to a switch
            if dst in self.net and len(self.net[dst].keys()) > 0:
                dst_switch = list(self.net[dst].keys())[0]

            if dst_switch is not None and dst_switch in self.labels[dpid] \
                    and len(self.labels[dpid][dst_switch]) > 0:
                # since dst is known, install flows to avoid future packet_ins
                table_id = self.default_table_id
                # match for ARP unicast
                priority = 1
                match = parser.OFPMatch(eth_dst=dst,
                        eth_type=ether_types.ETH_TYPE_ARP)
                # get ARP instructions
                for path in range(len(self.labels[dpid][dst_switch])):
                    if self.labels[dpid][dst_switch][path][3] < 1000:
                        try:
                            next_hop = self.labels[dpid][dst_switch][path][2][1]
                        except IndexError:
                            next_hop = self.labels[dpid][dst_switch][path][2][0]
                        next_hop_label = self.labels[dpid][dst_switch][path][4]
                        break
                out_port = self.net[dpid][next_hop]['port']
                actions = [parser.OFPActionPushMpls(),
                           parser.OFPActionSetField(
                               mpls_label=next_hop_label),
                           parser.OFPActionOutput(out_port)
                          ]
                instructions = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, priority, match, instructions, table_id)
                if eth.ethertype == ether_types.ETH_TYPE_ARP:
                    msg_actions = actions

                # match for non-ARP unicast that prioritizes latency
                priority = 2
                match = parser.OFPMatch(eth_dst=dst,
                        eth_type=ether_types.ETH_TYPE_IP)
                # get instructions for non-ARP unicast that prioritizes latency
                for path in range(len(self.labels[dpid][dst_switch])):
                    if self.labels[dpid][dst_switch][path][3] >= 1000:
                        try:
                            next_hop = self.labels[dpid][dst_switch][path][2][1]
                        except IndexError:
                            next_hop = self.labels[dpid][dst_switch][path][2][0]
                        next_hop_label = self.labels[dpid][dst_switch][path][4]
                        break
                out_port = self.net[dpid][next_hop]['port']
                actions = [parser.OFPActionPushMpls(),
                           parser.OFPActionSetField(
                               mpls_label=next_hop_label),
                           parser.OFPActionOutput(out_port)
                          ]
                instructions = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, priority, match, instructions, table_id)
                if eth.ethertype == ether_types.ETH_TYPE_IP:
                    msg_actions = actions

                # match for non-ARP unicast traffic that prioritizes bandwidth
                priority = 3
                for port in self.bw_ports:
                    next_hop = None
                    next_hop_label = None
                    # get instructions for non-ARP unicast that prioritizes bandwidth
                    for path in range(
                            len(self.labels[dpid][dst_switch])-1, -1, -1):
                        if self.labels[dpid][dst_switch][path][3] >= 1000:
                            try:
                                next_hop = self.labels[dpid][dst_switch][path][2][1]
                            except IndexError:
                                next_hop = self.labels[dpid][dst_switch][path][2][0]
                            next_hop_label = self.labels[dpid][dst_switch][path][4]
                            break
                    out_port = self.net[dpid][next_hop]['port']
                    actions = [parser.OFPActionPushMpls(),
                               parser.OFPActionSetField(
                                   mpls_label=next_hop_label),
                               parser.OFPActionOutput(out_port)
                              ]
                    instructions = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    # tcp match
                    match = parser.OFPMatch(eth_dst=dst,
                            eth_type=ether_types.ETH_TYPE_IP,
                            ip_proto=in_proto.IPPROTO_TCP,
                            tcp_dst=port)
                    self.add_flow(datapath, priority, match, instructions, table_id)
                    # udp match
                    match = parser.OFPMatch(eth_dst=dst,
                            eth_type=ether_types.ETH_TYPE_IP,
                            ip_proto=in_proto.IPPROTO_UDP,
                            udp_dst=port)
                    self.add_flow(datapath, priority, match, instructions, table_id)
                    if eth.ethertype == ether_types.ETH_TYPE_IP and \
                            pkt.get_protocol(ipv4.ipv4) is not None and \
                            (pkt.get_protocol(tcp.tcp) is not None or \
                             pkt.get_protocol(udp.udp) is not None):
                        msg_actions = actions


            # if dst_switch is not known, flood the packet
            if dst not in self.net or dst_switch is None:
                msg_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        if msg_actions is None:
            msg_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=msg_actions, data=data)

        datapath.send_msg(out)


    '''
    When the topology updates, rebuild the graph. This involves multiple steps:
        1. delete the existing graph in the controller
        2. delete all connected switches' flows
        3. rebuild the graph based on the current links info
        4. recalculate mpls labels
    After this, it should act just as it did on startup.
    '''
    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventSwitchLeave)
    def update_topology(self, ev):
        # clear graph and precomputed paths
        self.net.clear()
        self.labels = {}
        self.mac_to_port = {}

        # wait a moment for ryu's topology info to update
        sleep(0.05)

        # get switches and links from ryu.topology
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port':link.src.port_no})
                for link in links_list]

        # remove all the flows in the switches
        for switch in switch_list:
            self.remove_flows(switch.dp)

        # add switches and links to graph
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)
        #self.logger.info("switches: %s", str(switches))
        #self.logger.info("links: %s", str(links))
        # get link bandwidth info from file and add it to the graph
        bw_list = open('bandwidths.edgelist', 'rb')
        bw_graph = nx.read_edgelist(bw_list, nodetype=int, data=(('bw', float),) )
        bw_list.close()
        #self.logger.info("bw_graph.edges(): %s", str(bw_graph.edges()))

        for edge in bw_graph.edges(): # .edges() only returns ends, not data
            #self.logger.info("edge = %s", str(edge))
            # if the edge is not in the edgelist of known/expected edges or
            # the bw field for the edge is missing, use a default bandwidth
            link_bw = 1
            if edge in self.net.edges():
                #self.logger.info("edge %s in self.net.edges()", str(edge))
                try:
                    link_bw = bw_graph[edge[0]][edge[1]]['bw']
                    #self.logger.info("link_bw = %f", link_bw)
                except:
                    #self.logger.info("no link_bw found")
                    pass
            try:
                port01 = self.net[edge[0]][edge[1]]['port']
                port10 = self.net[edge[1]][edge[0]]['port']
                self.net.add_edge(edge[0],edge[1], {'port': port01,
                    'bw': link_bw})
                self.net.add_edge(edge[1],edge[0], {'port': port10,
                    'bw': link_bw})
            except KeyError:
                #self.logger.info("KeyError for edge %s", str(edge))
                continue

        # calculate labels
        #self.logger.info("calculating labels")
        self.labels = compute_mpls_labels(self.net)

        # add label-swapping flows to the switches
	for switch in switch_list:
            switch_id = switch.dp.id
            ofproto = self.switch_ofprotos[switch_id]
            parser = self.switch_parsers[switch_id]
            for dst in self.labels[switch_id].keys():
                for path in range(len(self.labels[switch_id][dst])):
                    # create a match for the path using its label
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_MPLS,
                            mpls_label=self.labels[switch_id][dst][path][3])
                    # determine actions the switch_id should take
                    if switch_id == dst:
                        # check if this is the ARP path or not
                        if self.labels[switch_id][dst][path][3] < 1000:
                            packet_ethertype = ether_types.ETH_TYPE_ARP
                        else:
                            packet_ethertype = ether_types.ETH_TYPE_IP
                        # create an instruction to pop the MPLS header
                        actions = [parser.OFPActionPopMpls(packet_ethertype)]
                        # create an instruction to go to the next table
                        table_instruction = parser.OFPInstructionGotoTable(
                                       self.mpls_dst_table_id)
                        instructions = [parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS, actions),
                                table_instruction]

                    else:
                        next_hop = self.labels[switch_id][dst][path][2][1]
                        next_hop_label = self.labels[switch_id][dst][path][4]
                        out_port = self.net[switch_id][next_hop]['port']
                        actions = [parser.OFPActionSetField(
                                        mpls_label = next_hop_label),
                                    parser.OFPActionDecMplsTtl(),
                                    parser.OFPActionOutput(out_port)
                                  ]
                        instructions = [parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS, actions)]

                    # now add the flow
                    self.add_flow(switch.dp, 1200, match, instructions,
                            self.default_table_id)
        self.print_graph()
        self.print_labels()
        print("")

