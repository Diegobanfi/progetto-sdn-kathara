from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp

#DEFINISCO IP PER TASK2
IP_H1 = "10.0.0.10"
IP_H2 = "10.0.0.20"

#FASE1:IDENTIFICO SWITCH E HOST, DEFINISCO DPID E IP
#DEFINISCO IP PER TASK3
IP_H3 = "10.0.0.30"

#DEFINISCO DPID SWITCH PER TASK3
DPID_S1 = 1
DPID_S2 = 2
DPID_S3 = 3

#FASE 2: DEFINISCO LE ROTTE STATICHE PER IL POLICY ROUTING PROATTIVO
STATIC_ROUTES = {
    # Andata : H1 -> S1 -> S3 -> S2 -> H2
    (DPID_S1, IP_H1, IP_H2): 4,
    (DPID_S3, IP_H1, IP_H2): 2,
    (DPID_S2, IP_H1, IP_H2): 2,
    # Ritorno : H2 -> S2 -> S1 -> H1 (non passa da S3)
    (DPID_S2, IP_H2, IP_H1): 1,
    (DPID_S1, IP_H2, IP_H1): 2,
}


#FASE5: Identifico porte inter-switch per evitare loop ARP sull'anello
SWITCH_PORTS = {
    DPID_S1: {1, 3, 4},   # porta1=r1, porta3=s2, porta4=s3
    DPID_S2: {1, 4},       # porta1=s1, porta4=s3
    DPID_S3: {1, 2},       # porta1=s1, porta2=s2
}


class RyuCampusController(app_manager.RyuApp): #SDN APPLICATION
    #implementa la logica decisionale
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuCampusController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table   = {}   # FASE 6{ip: mac} — globale su tutti gli switch

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _packet_out(self, datapath, in_port, actions, data, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        bid     = buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=bid,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

#FASE 3: INSTALLAZIONE PROATTIVA DELLE ROTTE STATICHE
#funzione una sola volta,quando lo switch si connette al controller

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Table-miss, priority 0: invia al controller tutti i pacchetti non matchati    
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self._install_static_routes(datapath) #installa le rotte statiche proattive per il policy routing
        self.logger.info(">>> Switch connesso: dpid=%016x", datapath.id)

#INSTALLAZIONE PROATTIVA ROUTE
    def _install_static_routes(self, datapath):
        parser = datapath.ofproto_parser
        dpid   = datapath.id #identifica lo switch corrente connesso al controller
        for (sw_dpid, src_ip, dst_ip), out_port in STATIC_ROUTES.items(): #percorre tutte le rotte statiche definite
            if sw_dpid != dpid:
                continue
            match   = parser.OFPMatch(eth_type=0x0800,ipv4_src=src_ip, ipv4_dst=dst_ip) #costo match identifica il traffico IP tra src e dst
            actions = [parser.OFPActionOutput(out_port)] #inoltro pacchetti verso la porta specificata per quella rotta 
            self._add_flow(datapath, priority=200, match=match, actions=actions) # aggiunge la regola al flusso dello switch corrente con priorità 200 
            self.logger.info("[dpid=%016x] ROUTE: %s→%s porta %s",dpid, src_ip, dst_ip, out_port)


#ESEGUO FUNZIONE SE HO UN PACKETIN DA UNO SWITCH E QUANDO LA CONNESSIONE TRA CONTROLLER E SWITCH è GIA STABILITA 
#quindi in questa funzione ryu riconosce se il pacchetto è un pacchetto ARP o un pacchetto IP 
# e gestisce il traffico in base alle regole definite nel controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        if eth.ethertype == 0x86DD:
            return

        # FIREWALL H1 ↔ H3 
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            #se il traffico è tra H1 e H3, applichiamo il blocco (DROP)
            if ((src_ip == IP_H1 and dst_ip == IP_H3) or
                    (src_ip == IP_H3 and dst_ip == IP_H1)):
                self.logger.warning("FIREWALL DROP: %s <-> %s", src_ip, dst_ip)
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=src_ip, ipv4_dst=dst_ip)
                self._add_flow(datapath, priority=300, match=match, actions=[])
                return

        # FASE6: GESTIONE ARP 
        arp_pkt = pkt.get_protocol(arp.arp) #controlla se il pacchetto è un pacchetto ARP(src_mac,src_ip,dst_ip,request/reply)
        if arp_pkt:
            #estraggo informazioni dal pacchetto ARP
            src_mac = arp_pkt.src_mac
            src_ip  = arp_pkt.src_ip
            dst_ip  = arp_pkt.dst_ip

            #serve al proxy arp in futuro
            self.arp_table[src_ip] = src_mac #memorizzo IP→MAC nella tabella ARP globale del controller
            self.mac_to_port[dpid][src_mac] = in_port #memorizzo la corrispondenza MAC→porta nella tabella mac_to_port
            self.logger.info("[dpid=%016x] ARP from %s(%s) porta %s",
                             dpid, src_ip, src_mac, in_port)

            #verifico se il pacchetto ARP è una richiesta 
            if arp_pkt.opcode == arp.ARP_REQUEST:
                # CASO 1: PROXY ARP REPLY: QUANDO IL MAC è GIA NOTO risponde direttamente controller ryu
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
                    #INVIO PACCHETTO ARP REPLY AL DESTINATARIO DA CONTROLLER
                    self._packet_out(datapath, ofproto.OFPP_CONTROLLER,
                                     [parser.OFPActionOutput(in_port)], p.data) 
                    return

                # CASO 2: MAC ASSOCIATO ALL'IP RICHIESTO SCONOSCIUTO: FLOOD SU PORTE HOST (NO LOOP)
                #PACCHETTO ARP REQUEST SENZA LOOP
                sw_ports = SWITCH_PORTS.get(dpid, set()) #recupero le porte che collegano lo switch agli altri switch 

                if in_port not in sw_ports: # ARP REQUEST da un HOST: flood su tutte le porte
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)] #ryu chiede allo switch di inviare il pacchetto su tutte le porte tranne quella di ingresso
                    self._packet_out(datapath, in_port, actions, msg.data,
                                     msg.buffer_id)
                else:# ARP REQUEST da un altro SWITCH: flood solo sulle porte host (non sw_ports) → no loop
                    #in_port appartiene a sw_ports
                    host_ports = []
                    for p_num in range(1, 5):
                        if p_num not in sw_ports:
                            host_ports.append(p_num)
                    for hp in host_ports:
                        if hp != in_port: 
                            self._packet_out(
                                datapath, in_port,
                                [parser.OFPActionOutput(hp)],
                                msg.data) #invio pacchetto ARP su tutte le porte host locali tranne quella di ingresso
                return

            #EVENTO ARP REPLY, AVVIENE IN UN PACCHETTO DISTINTO RISPETTO ALLA REQUEST
            elif arp_pkt.opcode == arp.ARP_REPLY:  # RYU RICEVE ARP reply: consegna al destinatario via MAC learning
                self.mac_to_port[dpid][src] = in_port #memorizzo la corrispondenza MAC→porta nella tabella mac_to_port
                if dst in self.mac_to_port[dpid]: #se conosco la porta del destinatario, invio il pacchetto direttamente a quella porta
                    out_port = self.mac_to_port[dpid][dst]
                    self._packet_out(datapath, in_port,
                                     [parser.OFPActionOutput(out_port)],
                                     msg.data, msg.buffer_id)
                else: #se non conosco la porta del destinatario, invio il pacchetto a tutte le porte tranne quella di ingresso (flood)
                    self._packet_out(datapath, in_port,
                                     [parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                                     msg.data, msg.buffer_id)
                return

        # MAC LEARNING FRAME ETHERNET generico 
        self.mac_to_port[dpid][src] = in_port
        out_port = (self.mac_to_port[dpid][dst] #se il destinatario è già conosciuto, invio il pacchetto direttamente a quella porta,Altrimenti invio il pacchetto a tutte le porte tranne quella di ingresso (flood)
                    if dst in self.mac_to_port[dpid]
                    else ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD: #se il destinatario è già conosciuto, aggiungo una regola di flusso per inoltrare direttamente i pacchetti futuri tra src e dst senza passare dal controller
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        self._packet_out(datapath, in_port, actions, data, msg.buffer_id) # packet_out invia il pacchetto al destinatario tramite la porta specificata