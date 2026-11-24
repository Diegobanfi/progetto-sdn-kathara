"""
ryu_campus.py - Ryu OpenFlow 1.3 controller for the ring-topology SDN lab.

Policies implemented (highest OpenFlow priority wins):

    priority 300  Firewall        : drop all IPv4 traffic between h1 and h3
                                    (installed reactively, per direction)
    priority 200  Policy routing  : static, asymmetric h1 <-> h2 paths over
                                    the ring (installed proactively)
    priority   1  MAC learning    : generic L2 forwarding for everything else
    priority   0  Table-miss      : send unmatched packets to the controller

Because s1, s2 and s3 form a physical loop, ARP broadcasts are never flooded
blindly between switches: the controller floods only the first hop and then
limits propagation to host-facing ports (controlled flooding), and answers
repeated requests itself (Proxy ARP).
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp

# ---------------------------------------------------------------------------
# Step 1 - Hosts and switches
# ---------------------------------------------------------------------------

# Host IP addresses (see lab/hX.startup)
IP_H1 = "10.0.0.10"   # workstation
IP_H2 = "10.0.0.20"   # web server
IP_H3 = "10.0.0.30"   # database server

# Datapath IDs, as configured with `other-config:datapath-id` in sX.startup.
# Ryu exposes them as integers (1 -> 0000000000000001).
DPID_S1 = 1
DPID_S2 = 2
DPID_S3 = 3

# ---------------------------------------------------------------------------
# Step 2 - Static policy-routing table
# ---------------------------------------------------------------------------
# (datapath id, source IP, destination IP) -> OpenFlow output port
#
# Port numbers are the OpenFlow ports assigned by Open vSwitch in the order
# the interfaces are added to each bridge (see lab/sX.startup):
#   s1: 1=r1  2=h1  3=s2  4=s3
#   s2: 1=s1  2=h2  3=h3  4=s3
#   s3: 1=s1  2=s2
STATIC_ROUTES = {
    # Forward path: h1 -> s1 -> s3 -> s2 -> h2   (detour through s3)
    (DPID_S1, IP_H1, IP_H2): 4,
    (DPID_S3, IP_H1, IP_H2): 2,
    (DPID_S2, IP_H1, IP_H2): 2,
    # Return path:  h2 -> s2 -> s1 -> h1         (direct, does not use s3)
    (DPID_S2, IP_H2, IP_H1): 1,
    (DPID_S1, IP_H2, IP_H1): 2,
}

# ---------------------------------------------------------------------------
# Step 5 - Inter-switch ports (used to stop ARP broadcasts looping on the ring)
# ---------------------------------------------------------------------------
# All remaining ports are host-facing (including the r1 uplink on s1).
SWITCH_PORTS = {
    DPID_S1: {3, 4},   # 3 = s2, 4 = s3
    DPID_S2: {1, 4},   # 1 = s1, 4 = s3
    DPID_S3: {1, 2},   # 1 = s1, 2 = s2
}

# Priorities of the flow rules installed by this controller
PRIO_FIREWALL = 300
PRIO_ROUTING = 200
PRIO_MAC_LEARNING = 1
PRIO_TABLE_MISS = 0


class RyuCampusController(app_manager.RyuApp):
    """SDN application: all forwarding decisions are taken here."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuCampusController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}   # {dpid: {mac: port}}  per-switch MAC learning
        self.arp_table = {}     # {ip: mac}            global, all switches

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """Install a flow rule (OFPFlowMod). Empty `actions` means DROP."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _packet_out(self, datapath, in_port, actions, data, buffer_id=None):
        """Send a packet through the switch (OFPPacketOut)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bid = buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=bid,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # -----------------------------------------------------------------------
    # Step 3 - Proactive installation of table-miss and static routes
    # -----------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs once per switch, when it connects to the controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss (priority 0): send every unmatched packet to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, PRIO_TABLE_MISS, match, actions)

        # Policy-routing flows for this switch
        self._install_static_routes(datapath)
        self.logger.info(">>> Switch connected: dpid=%016x", datapath.id)

    def _install_static_routes(self, datapath):
        """Install the entries of STATIC_ROUTES that belong to this switch."""
        parser = datapath.ofproto_parser
        dpid = datapath.id

        for (sw_dpid, src_ip, dst_ip), out_port in STATIC_ROUTES.items():
            if sw_dpid != dpid:
                continue  # entry is meant for another switch

            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, PRIO_ROUTING, match, actions)
            self.logger.info("[dpid=%016x] ROUTE: %s->%s port %s",
                             dpid, src_ip, dst_ip, out_port)

    # -----------------------------------------------------------------------
    # Packet-in handler: firewall, ARP handling, MAC learning
    # -----------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Called for every packet a switch sends up to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        # Ignore IPv6 (EtherType 0x86DD)
        if eth.ethertype == 0x86DD:
            return

        # ---- Firewall: block h1 <-> h3 (priority 300) ----------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            if ((src_ip == IP_H1 and dst_ip == IP_H3) or
                    (src_ip == IP_H3 and dst_ip == IP_H1)):
                self.logger.warning("FIREWALL DROP: %s <-> %s", src_ip, dst_ip)
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=src_ip, ipv4_dst=dst_ip)
                # No actions = drop. Later packets are dropped by the switch.
                self._add_flow(datapath, PRIO_FIREWALL, match, actions=[])
                return

        # ---- ARP handling (Step 6) ------------------------------------------
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_mac = arp_pkt.src_mac
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            # Learn IP->MAC (global) and MAC->port (per switch)
            self.arp_table[src_ip] = src_mac
            self.mac_to_port[dpid][src_mac] = in_port
            self.logger.info("[dpid=%016x] ARP from %s(%s) port %s",
                             dpid, src_ip, src_mac, in_port)

            if arp_pkt.opcode == arp.ARP_REQUEST:
                # Case 1 - Proxy ARP: the controller already knows the MAC,
                # so it answers directly and nothing is flooded on the ring.
                if dst_ip in self.arp_table:
                    reply_mac = self.arp_table[dst_ip]
                    self.logger.info(
                        "[dpid=%016x] ARP PROXY REPLY: %s is %s",
                        dpid, dst_ip, reply_mac)
                    e = ethernet.ethernet(dst=src_mac, src=reply_mac,
                                          ethertype=0x0806)
                    a = arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=reply_mac, src_ip=dst_ip,
                                dst_mac=src_mac, dst_ip=src_ip)
                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)
                    p.serialize()
                    self._packet_out(datapath, ofproto.OFPP_CONTROLLER,
                                     [parser.OFPActionOutput(in_port)], p.data)
                    return

                # Case 2 - unknown MAC: controlled flooding (no L2 loops)
                sw_ports = SWITCH_PORTS.get(dpid, set())

                if in_port not in sw_ports:
                    # Request from a host: flood on all ports except in_port
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    self._packet_out(datapath, in_port, actions, msg.data,
                                     msg.buffer_id)
                else:
                    # Request relayed by another switch: deliver only to the
                    # local host-facing ports, never back onto the ring.
                    host_ports = [p_num for p_num in range(1, 5)
                                  if p_num not in sw_ports]
                    for hp in host_ports:
                        if hp != in_port:
                            self._packet_out(
                                datapath, in_port,
                                [parser.OFPActionOutput(hp)],
                                msg.data)
                return

            elif arp_pkt.opcode == arp.ARP_REPLY:
                # Deliver the reply unicast if the destination port is known,
                # otherwise fall back to flooding.
                self.mac_to_port[dpid][src] = in_port
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                    self._packet_out(datapath, in_port,
                                     [parser.OFPActionOutput(out_port)],
                                     msg.data, msg.buffer_id)
                else:
                    self._packet_out(
                        datapath, in_port,
                        [parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                        msg.data, msg.buffer_id)
                return

        # ---- Generic MAC learning (Step 8, fallback) -------------------------
        self.mac_to_port[dpid][src] = in_port
        out_port = (self.mac_to_port[dpid][dst]
                    if dst in self.mac_to_port[dpid]
                    else ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Known destination: install a flow so later frames bypass the controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, PRIO_MAC_LEARNING, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        self._packet_out(datapath, in_port, actions, data, msg.buffer_id)
