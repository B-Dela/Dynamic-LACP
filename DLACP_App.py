from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
import logging
import time
from collections import defaultdict

class LACPApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LACPApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.lag_groups = {}
        self.link_stats = defaultdict(lambda: defaultdict(dict))
        self.active_ports = {}
        self.port_states = defaultdict(dict)
        self.web_server_ip = '10.0.0.1'
        self.max_links = 4
        self.port_capacity = 250000  # 250 Mbps per port
        self.min_ports = 2  # Minimum 2 ports for redundancy
        self.load_threshold = 0.85  # 85% utilization trigger
        logging.basicConfig(level=logging.INFO)  # Reduced verbosity
        logging.info("LACPApp initialized, listening for switch connections")

    def _send_packet_out(self, datapath, buffer_id, in_port, actions, data=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                in_port=in_port, actions=actions, data=data)
        try:
            datapath.send_msg(req)
        except Exception as e:
            logging.error(f"Failed to send packet out: {e}")

    def _configure_lag_group(self, datapath, ports, force=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        group_id = self.lag_groups.get(datapath.id, 1)
        if force and group_id >= 1:
            group_id += 1
        buckets = []
        last_good_ports = self.active_ports.get(datapath.id, list(range(1, 5)))  # Fallback to all ports
        for port in ports:
            state = self.port_states[datapath.id].get(port, {}).get('state', ofproto_v1_3.OFPPS_LINK_DOWN)
            if state & ofproto_v1_3.OFPPS_LINK_DOWN:
                logging.warning(f"Skipping port {port} for dp_id {datapath.id} as it is down")
                continue
            actions = [parser.OFPActionOutput(port)]
            bucket = parser.OFPBucket(actions=actions, weight=1)  # Equal weighting
            buckets.append(bucket)
        
        if not buckets or len(buckets) < self.min_ports:
            logging.error(f"Insufficient valid ports for LAG group on dp_id {datapath.id}, reverting to {last_good_ports}")
            if not force:
                self._configure_lag_group(datapath, last_good_ports, force=True)
            return

        command = ofproto.OFPGC_ADD if self.lag_groups.get(datapath.id) is None or force else ofproto.OFPGC_MODIFY
        mod = parser.OFPGroupMod(
            datapath=datapath,
            command=command,
            type_=ofproto.OFPGT_SELECT,
            group_id=group_id,
            buckets=buckets
        )
        start_time = time.time()
        for _ in range(3):
            try:
                datapath.send_msg(mod)
                self.lag_groups[datapath.id] = group_id
                self.active_ports[datapath.id] = [b.actions[0].port for b in buckets]
                logging.info(f"{'Added' if command == ofproto.OFPGC_ADD else 'Updated'} LAG group {group_id} for dp_id {datapath.id} with ports {self.active_ports[datapath.id]}")
                self._update_flows(datapath)
                return
            except Exception as e:
                elapsed = time.time() - start_time
                if elapsed > 5:
                    logging.error(f"Timeout configuring LAG group for dp_id {datapath.id}, using fallback {last_good_ports}")
                    self._configure_lag_group(datapath, last_good_ports, force=True)
                    return
                logging.error(f"Failed to configure LAG group: {e}, attempt {_ + 1}/3, group_id {group_id}")
                time.sleep(0.5)
        logging.error(f"Failed to configure LAG group after retries for dp_id {datapath.id}, forcing fallback with new group_id")
        self._configure_lag_group(datapath, last_good_ports, force=True)

    def _update_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        group_id = self.lag_groups.get(datapath.id, 1)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 80, match, actions)

        # High-priority flows for iperf3 UDP traffic
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=self.web_server_ip, udp_dst=5201)
        actions = [parser.OFPActionGroup(group_id=group_id)]
        self.add_flow(datapath, 70, match, actions)

        # High-priority flows for nping UDP traffic
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=self.web_server_ip, udp_dst=5202)
        actions = [parser.OFPActionGroup(group_id=group_id)]
        self.add_flow(datapath, 70, match, actions)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=self.web_server_ip)
        actions = [parser.OFPActionGroup(group_id=group_id)]
        self.add_flow(datapath, 60, match, actions)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL)]
        self.add_flow(datapath, 50, match, actions)

        # Ensure default flow doesn't shadow priority flows
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match, actions)  

        # Clear temporary flood
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            priority=80,
            match=parser.OFPMatch()
        )
        try:
            datapath.send_msg(mod)
        except Exception as e:
            logging.error(f"Failed to delete flood flow: {e}")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                              match=match, instructions=inst, buffer_id=ofproto.OFP_NO_BUFFER)
        try:
            datapath.send_msg(mod)
            logging.debug(f"Added flow: priority={priority}, match={match}, actions={actions}")
        except Exception as e:
            logging.error(f"Failed to add flow: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dp_id = datapath.id
        self.datapaths[dp_id] = datapath
        self.link_stats[dp_id] = {
            i: {'traffic': 0, 'last_traffic': 0, 'last_update': time.time()}
            for i in range(1, self.max_links + 1)
        }
        self.port_states[dp_id] = {i: {'state': 0} for i in range(1, self.max_links + 1)}
        self.active_ports[dp_id] = list(range(1, 5))  
        logging.info(f"Switch {dp_id} connected, configuring LAG with all 4 ports")
        self._configure_lag_group(datapath, self.active_ports[dp_id])
        self._request_port_stats(datapath)
        self._request_port_desc_stats(datapath)
       
        active_ports_set = set(self.active_ports[dp_id])
        for port in range(1, 5):
            state = self.port_states[dp_id].get(port, {}).get('state', 0)
            if not state & ofproto_v1_3.OFPPS_LINK_DOWN:
                active_ports_set.add(port)
        self.active_ports[dp_id] = list(active_ports_set)
        self._configure_lag_group(datapath, self.active_ports[dp_id])

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dp_id = datapath.id
        for stat in ev.msg.body:
            port_no = stat.port_no
            if port_no <= self.max_links:
                current_traffic = stat.rx_bytes + stat.tx_bytes
                self.link_stats[dp_id][port_no]['traffic'] = current_traffic
                self._adjust_links(dp_id, current_traffic, port_no)
                logging.debug(f"Port stats for dp_id {dp_id}, port {port_no}: {current_traffic} bytes")

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dp_id = datapath.id
        for desc in ev.msg.body:
            port_no = desc.port_no
            if port_no <= self.max_links:
                self.port_states[dp_id][port_no] = {'state': desc.state}
                logging.debug(f"Port desc for dp_id {dp_id}, port {port_no}: state {desc.state}")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dp_id = datapath.id
        port_no = msg.desc.port_no
        if port_no <= self.max_links:
            self.port_states[dp_id][port_no] = {'state': msg.desc.state}
            if msg.reason == ofproto_v1_3.OFPPR_DELETE or msg.desc.state & ofproto_v1_3.OFPPS_LINK_DOWN:
                if port_no in self.active_ports.get(dp_id, []):
                    self.active_ports[dp_id].remove(port_no)
                    logging.info(f"Port {port_no} down, removed from LAG for dp_id {dp_id}")
                    self._configure_lag_group(datapath, self.active_ports[dp_id])
            elif not msg.desc.state & ofproto_v1_3.OFPPS_LINK_DOWN and port_no not in self.active_ports.get(dp_id, []):
                logging.info(f"Port {port_no} up, re-adding to LAG for dp_id {dp_id}")
                self.active_ports[dp_id].append(port_no)
                self._configure_lag_group(datapath, self.active_ports[dp_id])

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ALL)
        try:
            datapath.send_msg(req)
            logging.debug(f"Requested port stats for dp_id {datapath.id}")
        except Exception as e:
            logging.error(f"Failed to request port stats: {e}")

    def _request_port_desc_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        try:
            datapath.send_msg(req)
            logging.debug(f"Requested port desc stats for dp_id {datapath.id}")
        except Exception as e:
            logging.error(f"Failed to request port desc stats: {e}")

    def _adjust_links(self, dp_id, current_traffic, port_no):
        datapath = self.datapaths.get(dp_id)
        if not datapath:
            return
        current_ports = self.active_ports.get(dp_id, list(range(1, 5)))
        all_possible_ports = set(range(1, self.max_links + 1))
        active_port_set = set(current_ports)
        available_ports = sorted(list(all_possible_ports - active_port_set))
        num_active_ports = len(current_ports)
        available_bandwidth_capacity = num_active_ports * self.port_capacity

       
        window_size = 5
        traffic_history = self.link_stats[dp_id][port_no].get('traffic_history', [0] * window_size)
        traffic_history.append(current_traffic)
        traffic_history = traffic_history[-window_size:]
        self.link_stats[dp_id][port_no]['traffic_history'] = traffic_history
        moving_average = sum(traffic_history) / window_size if traffic_history else current_traffic

        last_traffic = self.link_stats[dp_id][port_no].get('last_traffic', 0)
        elapsed = time.time() - self.link_stats[dp_id][port_no].get('last_update', time.time())
        bandwidth = ((moving_average - last_traffic) * 8) / (elapsed * 1024) if elapsed > 0 else 0
        total_bandwidth = sum(
            ((self.link_stats[dp_id][p].get('traffic_history', [0] * window_size)[-1] - 
              self.link_stats[dp_id][p].get('last_traffic', 0)) * 8) / (elapsed * 1024)
            if elapsed > 0 else 0
            for p in current_ports
        )

       
        add_threshold = self.load_threshold * available_bandwidth_capacity
        remove_threshold = 0.15 * available_bandwidth_capacity
        hysteresis = 0.1 * available_bandwidth_capacity
        effective_load = total_bandwidth

        if effective_load > add_threshold + hysteresis and num_active_ports < self.max_links and available_ports:
            for port in available_ports:
                state = self.port_states[dp_id].get(port, {}).get('state', ofproto_v1_3.OFPPS_LINK_DOWN)
                if not state & ofproto_v1_3.OFPPS_LINK_DOWN:
                    current_ports.append(port)
                    self.active_ports[dp_id] = current_ports
                    logging.info(f"Added port {port} for dp_id {dp_id} due to high load, total ports: {len(current_ports)}")
                    self._configure_lag_group(datapath, current_ports)
                    break
        elif effective_load < remove_threshold - hysteresis and num_active_ports > self.min_ports:
            least_loaded_port = min(current_ports, key=lambda p: self.link_stats[dp_id][p].get('traffic_history', [0] * window_size)[-1])
            if least_loaded_port != port_no and len(current_ports) > self.min_ports:
                current_ports.remove(least_loaded_port)
                self.active_ports[dp_id] = current_ports
                logging.info(f"Removed port {least_loaded_port} for dp_id {dp_id} due to low load, total ports: {len(current_ports)}")
                self._configure_lag_group(datapath, current_ports)

        self.link_stats[dp_id][port_no]['last_traffic'] = moving_average
        self.link_stats[dp_id][port_no]['last_update'] = time.time()

class MockHub:
    def sleep(self, seconds):
        time.sleep(seconds)

if __name__ == "__main__":
    from ryu.cmd import manager
    manager.main()
