# Dynamic LACP Ryu application
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lacp
from ryu.lib import hub
from operator import attrgetter # For sorting port stats
from ryu import cfg # For configuration
import json # For parsing potential_lags config
import threading

# LACP constants
LACP_MAC_ADDRESS = "01:80:c2:00:00:02" # Standard LACP MAC
LACP_SUBTYPE = 0x01                 # LACP Subtype
LACP_VERSION = 0x01                 # LACP Version
LACP_ACTOR_SYSTEM_PRIORITY = 0xFFFF # Default System Priority (can be configured if needed)
# LACP_ACTOR_KEY will be from config
# LACP_PORT_PRIORITY will be from config
LACP_TIMEOUT_SHORT = 1      # Standard LACP short timeout (seconds)
LACP_TIMEOUT_LONG = 3       # Standard LACP long timeout (seconds)

# Default values for configuration options if not provided
DEFAULT_LACP_ACTOR_KEY = 0x0001
DEFAULT_LACP_PORT_PRIORITY = 0xFF
DEFAULT_STATS_INTERVAL = 20 # Updated to 20 seconds
DEFAULT_MAX_LINK_MBPS = 1000
DEFAULT_BUNDLING_THRESHOLD_PERCENT = 0.8
DEFAULT_UNBUNDLING_THRESHOLD_FACTOR = 0.7
DEFAULT_POTENTIAL_LAGS_JSON = '{}'


CONF_OPTS = [
    cfg.StrOpt('potential_lags_json', default=DEFAULT_POTENTIAL_LAGS_JSON,
               help='JSON string describing potential LAGs. '
                    'Example: \'{"1": {"lag1": [1, 2], "lag2": [3, 4]}}\' '
                    'This defines for datapath ID "1": '
                    'lag_id "lag1" can be formed by physical ports 1 and 2. '
                    'lag_id "lag2" can be formed by physical ports 3 and 4.'),
    cfg.IntOpt('lacp_actor_key', default=DEFAULT_LACP_ACTOR_KEY, help='LACP actor key for the controller.'),
    cfg.IntOpt('lacp_port_priority', default=DEFAULT_LACP_PORT_PRIORITY, help='LACP port priority for controlled ports.'),
    cfg.IntOpt('stats_interval', default=DEFAULT_STATS_INTERVAL, help='Port statistics request interval in seconds.'),
    cfg.IntOpt('max_link_mbps', default=DEFAULT_MAX_LINK_MBPS, help='Default maximum link bandwidth in Mbps (used for threshold calculations).'),
    cfg.FloatOpt('bundling_threshold_percent', default=DEFAULT_BUNDLING_THRESHOLD_PERCENT, 
                 help='Link utilization percentage (0.0 to 1.0) of max_link_mbps to trigger LACP activation for bundling.'),
    cfg.FloatOpt('unbundling_threshold_factor', default=DEFAULT_UNBUNDLING_THRESHOLD_FACTOR, 
                 help='Factor (0.0 to 1.0) of a single link\'s max_link_mbps. If a LAG\'s total bandwidth drops below this, consider LACP deactivation.')
]
class LacpPortInfo:
    def __init__(self, port_no, hw_addr, actor_system_id, actor_key, actor_port_priority):
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.actor_system_id = actor_system_id 
        self.actor_key = actor_key 
        self.actor_port_priority = actor_port_priority
        self.actor_port_id = port_no

        self.actor_state_activity = 0 
        self.actor_state_timeout = lacp.LACP_STATE_TIMEOUT_LONG
        self.actor_state_aggregation = 0
        self.actor_state_synchronization = 0
        self.actor_state_collecting = 0
        self.actor_state_distributing = 0
        self.actor_state_defaulted = 0
        self.actor_state_expired = 0

        self.partner_system_id = "00:00:00:00:00:00"
        self.partner_key = 0
        self.partner_port_priority = 0xFF
        self.partner_port_id = 0
        self.partner_state_activity = 0
        self.partner_state_timeout = lacp.LACP_STATE_TIMEOUT_LONG
        self.partner_state_aggregation = 0
        self.partner_state_synchronization = 0
        self.partner_state_collecting = 0
        self.partner_state_distributing = 0
        self.partner_state_defaulted = 1 
        self.partner_state_expired = 0

        self.last_lacpdu_rx_time = 0
        self.last_lacpdu_tx_time = 0

    def is_active(self):
        return self.actor_state_activity == lacp.LACP_STATE_ACTIVE

    def is_partner_active(self):
        return self.partner_state_activity == lacp.LACP_STATE_ACTIVE

    def __str__(self):
        return (f"LacpPortInfo(p={self.port_no}, actor_key={self.actor_key}, partner_key={self.partner_key}, "
                f"sync={self.actor_state_synchronization}, agg={self.actor_state_aggregation})")
    
CONF_GROUP = 'lacp_app' 
class LacpApp(app_manager.RyuApp): 
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LacpApp, self).__init__(*args, **kwargs)
        self.data_lock = threading.Lock()
        
        self.conf = cfg.CONF
        self.conf.register_opts(CONF_OPTS, group=CONF_GROUP)
        self.app_opts = self.conf[CONF_GROUP]

        self.mac_to_port = {}
        self.datapaths = {} 
        self.lacp_ports = {} 
        self.lags = {} 

        try:
            # Configured format: {"dpid_str": {"lag_id_str": [port1, port2]}}
            # Internal format `self.potential_lags`: {dpid_int: {port_int: "lag_id_str"}}
            raw_lags_config = json.loads(self.app_opts.potential_lags_json)
            self.potential_lags = {}
            for dpid_str, lag_defs in raw_lags_config.items():
                dpid = int(dpid_str)
                self.potential_lags.setdefault(dpid, {})
                for lag_id, ports in lag_defs.items():
                    for port_no in ports:
                        if not isinstance(port_no, int) or port_no <= 0 or port_no == ofproto_v1_3.OFPP_LOCAL:
                            self.logger.error("Invalid port %s in lag %s for dpid %s", port_no, lag_id, dpid)
                            continue
                        self.potential_lags[dpid][int(port_no)] = lag_id
            self.logger.info("Parsed potential_lags: %s", self.potential_lags)
        except ValueError as e: # Handles JSON parsing errors
            self.logger.error("Failed to parse potential_lags_json: %s. Using default: {}", e,)
            self.potential_lags = {} #json.loads(DEFAULT_POTENTIAL_LAGS_JSON) # Should result in {}

        # Assign configured values to instance variables for easier access
        self.LACP_ACTOR_KEY = self.app_opts.lacp_actor_key
        self.LACP_PORT_PRIORITY = self.app_opts.lacp_port_priority
        self.STATS_REQUEST_INTERVAL = self.app_opts.stats_interval
        self.MAX_LINK_BANDWIDTH_MBPS = self.app_opts.max_link_mbps
        self.BUNDLING_THRESHOLD_PERCENT = self.app_opts.bundling_threshold_percent
        self.UNBUNDLING_THRESHOLD_FACTOR = self.app_opts.unbundling_threshold_factor

        self.logger.info("LACP Application Configuration:")
        self.logger.info("  potential_lags: %s", self.potential_lags)
        self.logger.info("  lacp_actor_key: 0x%04x", self.LACP_ACTOR_KEY)
        self.logger.info("  lacp_port_priority: 0x%02x", self.LACP_PORT_PRIORITY)
        self.logger.info("  stats_interval: %d s", self.STATS_REQUEST_INTERVAL)
        self.logger.info("  max_link_mbps: %d Mbps", self.MAX_LINK_BANDWIDTH_MBPS)
        self.logger.info("  bundling_threshold_percent: %.2f%%", self.BUNDLING_THRESHOLD_PERCENT * 100)
        self.logger.info("  unbundling_threshold_factor: %.2f", self.UNBUNDLING_THRESHOLD_FACTOR)
        
        self.lacp_reply_thread = hub.spawn(self._lacp_reply_loop)
        self.port_stats = {} # To store (timestamp, byte_count) for bandwidth calculation
                            # Structure: {dpid: {port_no: {'timestamp': float, 'bytes': int, 'bandwidth_mbps': float}}}
        self.stats_thread = hub.spawn(self._monitor_stats_loop)
        self.lag_to_group_id = {} # dpid -> {lag_id -> group_id}
        self.group_id_allocator = {} # dpid -> next_available_group_id

    def _get_next_group_id(self, dpid):
        self.group_id_allocator.setdefault(dpid, 1) # Group IDs are > 0
        group_id = self.group_id_allocator[dpid]
        self.group_id_allocator[dpid] += 1
        return group_id

    def _lacp_reply_loop(self):
        while True:
            current_time = hub.now()  # Moved from line 174 to 173
            with self.data_lock:
                for dpid, dp in self.datapaths.items():
                    for port_no, port_info in self.lacp_ports.get(dpid, {}).items():
                        timeout = LACP_TIMEOUT_LONG if port_info.partner_state_timeout else LACP_TIMEOUT_SHORT
                        if port_info.last_lacpdu_rx_time and (current_time - port_info.last_lacpdu_rx_time > timeout):
                            port_info.actor_state_expired = lacp.LACP_STATE_EXPIRED
                            port_info.actor_state_synchronization = 0
                            port_info.actor_state_collecting = 0
                            port_info.actor_state_distributing = 0
                            self.logger.info("LACP timeout on dpid %s port %s", dpid, port_no)
                            self._update_lag_membership(dpid, port_no, remove=True)
                        if port_info.is_active():
                            self._send_lacpdu(dp, port_no, port_info)
            hub.sleep(LACP_TIMEOUT_SHORT)
    
    def _send_lacpdu(self, datapath, port_no, port_info):
    
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        if port_no not in datapath.ports:
            self.logger.error("Port %s not found in datapath %s", port_no, datapath.id)
            return
        try:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_SLOW,
                                            src=datapath.ports[port_no].hw_addr, # Use port's MAC
                                            dst=LACP_MAC_ADDRESS))
            
            actor_state = port_info.actor_state_activity | \
                        port_info.actor_state_timeout | \
                        port_info.actor_state_aggregation | \
                        port_info.actor_state_synchronization | \
                        port_info.actor_state_collecting | \
                        port_info.actor_state_distributing | \
                        port_info.actor_state_defaulted | \
                        port_info.actor_state_expired

            partner_system_id = port_info.partner_system_id if port_info.partner_system_id else "00:00:00:00:00:00"
            partner_key = port_info.partner_key if port_info.partner_key else 0
            partner_port_id = port_info.partner_port_id if port_info.partner_port_id else 0
            partner_port_priority = port_info.partner_port_priority if port_info.partner_port_priority else 0xFF
            
            l = lacp.lacp(version=LACP_VERSION,
                        subtype=LACP_SUBTYPE,
                        actor_system_priority=LACP_ACTOR_SYSTEM_PRIORITY,
                        actor_system=datapath.address, 
                        actor_key=port_info.actor_key, 
                        actor_port_priority=port_info.actor_port_priority, # Use configured port priority
                        actor_port=port_no,
                        actor_state_activity=port_info.actor_state_activity,
                        actor_state_timeout=port_info.actor_state_timeout,
                        actor_state_aggregation=port_info.actor_state_aggregation,
                        actor_state_synchronization=port_info.actor_state_synchronization,
                        actor_state_collecting=port_info.actor_state_collecting,
                        actor_state_distributing=port_info.actor_state_distributing,
                        actor_state_defaulted=port_info.actor_state_defaulted,
                        actor_state_expired=port_info.actor_state_expired,
                        partner_system_priority=LACP_ACTOR_SYSTEM_PRIORITY, 
                        partner_system=partner_system_id,
                        partner_key=partner_key,
                        partner_port_priority=partner_port_priority,
                        partner_port=partner_port_id,
                        partner_state_activity=port_info.partner_state_activity,
                        partner_state_timeout=port_info.partner_state_timeout,
                        partner_state_aggregation=port_info.partner_state_aggregation,
                        partner_state_synchronization=port_info.partner_state_synchronization,
                        partner_state_collecting=port_info.partner_state_collecting,
                        partner_state_distributing=port_info.partner_state_distributing,
                        partner_state_defaulted=port_info.partner_state_defaulted,
                        partner_state_expired=port_info.partner_state_expired,
                        collector_max_delay=0)
            pkt.add_protocol(l)
            actions = [parser.OFPActionOutput(port_no)]
            out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=pkt.data)
            datapath.send_msg(out)
        except Exception as e:
            self.logger.error("Failed to send LACPDU on dpid %s port %s: %s", datapath.id, port_no, e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected (DPID: %s, Addr: %s).", datapath.id, datapath.id, datapath.address)
        self.datapaths[datapath.id] = datapath
        self.lacp_ports.setdefault(datapath.id, {})

        for port_no, port_features in datapath.ports.items():
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                if datapath.id in self.potential_lags and port_no in self.potential_lags[datapath.id]:
                    self.initialize_lacp_port(datapath, port_no, port_features.hw_addr)
                    self.logger.info("Initialized LACP on dpid %s port %s (MAC: %s)", 
                                     datapath.id, port_no, port_features.hw_addr)

    def initialize_lacp_port(self, datapath, port_no, port_mac):
        dpid = datapath.id
        # Pass the configured LACP actor key and port priority to LacpPortInfo
        self.lacp_ports[dpid][port_no] = LacpPortInfo(
            port_no=port_no,
            hw_addr=port_mac,
            actor_system_id=datapath.address,
            actor_key=self.LACP_ACTOR_KEY,
            actor_port_priority=self.LACP_PORT_PRIORITY
        )
        self.lacp_ports[dpid][port_no].actor_state_activity = lacp.LACP_STATE_ACTIVE

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        if eth.dst == LACP_MAC_ADDRESS and eth.ethertype == ether_types.ETH_TYPE_SLOW:
            lacp_pkt = pkt.get_protocol(lacp.lacp)
            if lacp_pkt and lacp_pkt.subtype == LACP_SUBTYPE:
                self._handle_lacp_packet(datapath, in_port, lacp_pkt, eth.src)
                return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_physical_port = self.mac_to_port[dpid][dst]
            # Check if this physical port is part of an active LAG
            active_lag_id = None
            active_group_id = None
            for lag_id, member_ports in self.lags.get(dpid, {}).items():
                if out_physical_port in member_ports:
                    active_lag_id = lag_id
                    break
            
            if active_lag_id:
                active_group_id = self.lag_to_group_id.get(dpid, {}).get(active_lag_id)

            if active_group_id:
                actions = [parser.OFPActionGroup(active_group_id)]
                out_port_for_flow_mod = active_group_id # conceptually, for logging or internal state
                self.logger.debug("DPID %s: Packet to %s (via port %s) is on active LAG %s (group %s). Using group action.",
                                 dpid, dst, out_physical_port, active_lag_id, active_group_id)
            else:
                actions = [parser.OFPActionOutput(out_physical_port)]
                out_port_for_flow_mod = out_physical_port
        else:
            # Destination MAC unknown, flood
            out_physical_port = ofproto.OFPP_FLOOD 
            actions = [parser.OFPActionOutput(out_physical_port)]
            out_port_for_flow_mod = out_physical_port # For consistency in add_flow logic if it were to use it

        # Install a flow to avoid packet_in next time
        # Note: out_port_for_flow_mod is conceptual here. The `actions` list is what's actually installed.
        if out_physical_port != ofproto.OFPP_FLOOD: 
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return # Packet is handled by the switch due to buffer_id
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_lacp_packet(self, datapath, in_port, lacp_pkt, eth_src):
        dpid = datapath.id
        with self.data_lock:  # Extended to cover lines 531–569
            if dpid not in self.lacp_ports or in_port not in self.lacp_ports[dpid]:
                self.logger.warning("LACPDU on unconfigured port %s dpid %s", in_port, dpid)
                if dpid in self.potential_lags and in_port in self.potential_lags[dpid]:
                    self.initialize_lacp_port(datapath, in_port, datapath.ports[in_port].hw_addr)
                    self.logger.info("Dynamically initialized LACP for dpid %s port %s", dpid, in_port)
                else:
                    return

            port_info = self.lacp_ports[dpid][in_port]
            port_info.partner_system_id = lacp_pkt.actor_system
            port_info.partner_key = lacp_pkt.actor_key
            port_info.partner_port_id = lacp_pkt.actor_port
            port_info.partner_port_priority = lacp_pkt.actor_port_priority
            port_info.partner_state_activity = lacp_pkt.actor_state_activity
            port_info.partner_state_timeout = lacp_pkt.actor_state_timeout
            port_info.partner_state_aggregation = lacp_pkt.actor_state_aggregation
            port_info.partner_state_synchronization = lacp_pkt.actor_state_synchronization
            port_info.partner_state_collecting = lacp_pkt.actor_state_collecting
            port_info.partner_state_distributing = lacp_pkt.actor_state_distributing
            port_info.partner_state_defaulted = lacp_pkt.actor_state_defaulted
            port_info.partner_state_expired = lacp_pkt.actor_state_expired
            port_info.last_lacpdu_rx_time = hub.now()

            if port_info.is_active() and port_info.is_partner_active() and \
            port_info.actor_key == port_info.partner_key and \
            port_info.actor_system_id == datapath.address and \
            port_info.partner_system_id != "00:00:00:00:00:00":
                port_info.actor_state_aggregation = lacp.LACP_STATE_AGGREGATION
                port_info.actor_state_synchronization = lacp.LACP_STATE_SYNCHRONIZATION
                if port_info.actor_state_synchronization:
                    port_info.actor_state_collecting = lacp.LACP_STATE_COLLECTING
                    port_info.actor_state_distributing = lacp.LACP_STATE_DISTRIBUTING
                actions = self._update_lag_membership(dpid, in_port)
            else:
                port_info.actor_state_aggregation = 0
                port_info.actor_state_synchronization = 0
                port_info.actor_state_collecting = 0
                port_info.actor_state_distributing = 0
                actions = self._update_lag_membership(dpid, in_port, remove=True)

            for action_type, lag_id, members in actions:
                if action_type == 'delete':
                    self._delete_lag_group(dpid, lag_id)
                elif action_type == 'modify':
                    self._add_or_modify_lag_group(dpid, lag_id, members)
            # self.logger.info("LACP: Port %s dpid %s INDIVIDUAL", in_port, dpid)
            self._update_lag_membership(dpid, in_port, remove=True)

    def _update_lag_membership(self, dpid, port_no, remove=False):
        actions = []
        self.lags.setdefault(dpid, {})
        port_info = self.lacp_ports[dpid].get(port_no)
        if not port_info:
            return actions

        potential_lag_id = self.potential_lags.get(dpid, {}).get(port_no)
        if not potential_lag_id:
            return actions

        lag_existed_before = potential_lag_id in self.lags.get(dpid, {})
        current_members_before = list(self.lags.get(dpid, {}).get(potential_lag_id, []))

        if remove or not (port_info.actor_state_aggregation and port_info.actor_state_synchronization):
            if potential_lag_id in self.lags.get(dpid, {}) and port_no in self.lags[dpid][potential_lag_id]:
                self.lags[dpid][potential_lag_id].remove(port_no)
                self.logger.info("Port %s removed from LAG %s on dpid %s. Remaining members: %s",
                             port_no, potential_lag_id, dpid, self.lags[dpid].get(potential_lag_id, []))
                if not self.lags[dpid].get(potential_lag_id, []):
                    if potential_lag_id in self.lags[dpid]:
                        del self.lags[dpid][potential_lag_id]
                    self.logger.info("LAG %s on dpid %s is now empty and removed.", potential_lag_id, dpid)
                    actions.append(('delete', potential_lag_id, []))
                else:
                    actions.append(('modify', potential_lag_id, self.lags[dpid][potential_lag_id]))
            return actions

        can_form_lag = True
        for other_port_no, lag_id in self.potential_lags.get(dpid, {}).items():
            if lag_id == potential_lag_id and other_port_no != port_no:
                other_port_info = self.lacp_ports[dpid].get(other_port_no)
                if not (other_port_info and
                    other_port_info.actor_state_aggregation and
                    other_port_info.actor_state_synchronization and
                    other_port_info.partner_system_id == port_info.partner_system_id and
                    other_port_info.partner_key == port_info.partner_key):
                    can_form_lag = False
                break

        if can_form_lag:
            self.lags[dpid].setdefault(potential_lag_id, [])
            if port_no not in self.lags[dpid][potential_lag_id]:
                self.lags[dpid][potential_lag_id].append(port_no)
                self.logger.info("Port %s added to LAG %s dpid %s. Members: %s",
                             port_no, potential_lag_id, dpid, self.lags[dpid][potential_lag_id])
                actions.append(('modify', potential_lag_id, self.lags[dpid][potential_lag_id]))
        else:
            if lag_existed_before and port_no in current_members_before:
                self.lags[dpid][potential_lag_id].remove(port_no)
                self.logger.info("Port %s implicitly removed from LAG %s dpid %s (can_form_lag=False). Remaining: %s",
                             port_no, potential_lag_id, dpid, self.lags[dpid].get(potential_lag_id, []))
            if not self.lags[dpid].get(potential_lag_id, []):
                if potential_lag_id in self.lags[dpid]:
                    del self.lags[dpid][potential_lag_id]
                self.logger.info("LAG %s on dpid %s empty (implicit removal). Deleting group.", potential_lag_id, dpid)
                actions.append(('delete', potential_lag_id, []))
            else:
                actions.append(('modify', potential_lag_id, self.lags[dpid][potential_lag_id]))

        return actions

    def _add_or_modify_lag_group(self, dpid, lag_id, member_ports):
        datapath = self.datapaths.get(dpid)
        if not datapath:
            self.logger.error("DPID %s: Datapath not found for group operation on LAG '%s'", dpid, lag_id)
            return actions
        
        #if not member_ports:
        #     self.logger.warning("DPID %s: Attempted to add/modify group for LAG '%s' with no members. Ensuring deletion.", dpid, lag_id)
         #    self._delete_lag_group(dpid, lag_id)
          #   return actions
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.lag_to_group_id.setdefault(dpid, {})

        group_id = self.lag_to_group_id[dpid].get(lag_id)
        cmd = ofproto.OFPGC_ADD
        if group_id is None:
            group_id = self._get_next_group_id(dpid)
            self.lag_to_group_id[dpid][lag_id] = group_id
            self.logger.info("DPID %s: Adding new LAG group: lag_id '%s', group_id %s, members %s",
                             dpid, lag_id, group_id, member_ports)
        else:
            cmd = ofproto.OFPGC_MODIFY
            self.logger.info("DPID %s: Modifying LAG group: lag_id '%s', group_id %s, new members %s",
                             dpid, lag_id, group_id, member_ports)

        buckets = []
        for port_no_member in member_ports:
            actions = [parser.OFPActionOutput(port_no_member)]
            # Using watch_port ensures group adapts if a member port goes down.
            buckets.append(parser.OFPBucket(weight=1, watch_port=port_no_member, 
                                            watch_group=ofproto.OFPG_ANY, actions=actions))
        
        if not buckets: # Should be caught by 'if not member_ports' earlier
            self.logger.error("DPID %s: No buckets generated for GroupMod on LAG '%s', members %s. Aborting.", dpid, lag_id, member_ports)
            if group_id is not None: # If a group_id was allocated/existed, try to clean up
                self._delete_lag_group(dpid, lag_id)
            return

        req = parser.OFPGroupMod(datapath, cmd, ofproto.OFPGT_SELECT, group_id, buckets)
        try:
            datapath.send_msg(req)
        except Exception as e:
            self.logger.error("Failed to send GroupMod for dpid %s lag_id %s: %s", dpid, lag_id, e)
            self.logger.debug("DPID %s: Sent GroupMod (cmd %s) for group %s, LAG '%s', members %s", 
                         cmd, dpid, group_id, lag_id, member_ports)

    def _delete_lag_group(self, dpid, lag_id):
        datapath = self.datapaths.get(dpid)
        if not datapath:
            self.logger.error("DPID %s: Datapath not found for group deletion on LAG '%s'", dpid, lag_id)
            return

        self.lag_to_group_id.setdefault(dpid, {})
        group_id = self.lag_to_group_id[dpid].pop(lag_id, None) # Remove from our mapping

        if group_id is not None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.logger.info("DPID %s: Deleting LAG group: lag_id '%s', group_id %s", dpid, lag_id, group_id)
            # For OFPGC_DELETE, buckets list must be empty.
            req = parser.OFPGroupMod(datapath, ofproto.OFPGC_DELETE, ofproto.OFPGT_SELECT, group_id, buckets=[])
            try:
                datapath.send_msg(req)
            except Exception as e:
                self.logger.error("Failed to send GroupMod for dpid %s lag_id %s: %s", dpid, lag_id, e)
        else:
            self.logger.debug("DPID %s: Attempted to delete group for LAG '%s', but no group_id was mapped.", lag_id, dpid)


    def _request_port_stats(self, datapath):
              # self.logger.debug("Requesting port stats for datapath %s", datapath.id)
            try:
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
           
                datapath.send_msg(req)
            except Exception as e:
                self.logger.error("Failed to request port stats for datapath %s: %s", datapath.id, e)
                
    def _monitor_stats_loop(self):
        while True:
            try:
                if self.datapaths:
                    for dp in self.datapaths.values():
                        self._request_port_stats(dp)
                hub.sleep(self.STATS_REQUEST_INTERVAL)
            except Exception as e:
                self.logger.error("Error in _monitor_stats_loop: %s", e)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.port_stats.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL: # Exclude local port
                current_time = hub.now()
                # Consider rx_bytes + tx_bytes for total link utilization
                current_bytes = stat.rx_bytes + stat.tx_bytes 

                if port_no in self.port_stats[dpid] and 'bytes' in self.port_stats[dpid][port_no]:
                    last_stat = self.port_stats[dpid][port_no]
                    time_diff = current_time - last_stat['timestamp']
                    byte_diff = current_bytes - last_stat['bytes']

                    if time_diff > 0:
                        bandwidth_mbps = (byte_diff * 8) / (time_diff * 1000000.0)
                        self.port_stats[dpid][port_no]['bandwidth_mbps'] = max(0, bandwidth_mbps)
                    else:
                        self.logger.debug("Invalid time_diff %s for dpid %s port %s, skipping bandwidth calculation", time_diff, dpid, port_no)
                        self.port_stats[dpid][port_no]['bandwidth_mbps'] = 0.0
                else: 
                     self.port_stats[dpid][port_no] = {'bandwidth_mbps': 0.0}

                self.port_stats[dpid][port_no]['timestamp'] = current_time
                self.port_stats[dpid][port_no]['bytes'] = current_bytes
                # self.port_stats[dpid][port_no]['rx_bytes'] = stat.rx_bytes # Store raw counters too
                # self.port_stats[dpid][port_no]['tx_bytes'] = stat.tx_bytes

                # Trigger dynamic link bundling logic based on this bandwidth
                self._check_bandwidth_thresholds(dpid, port_no)

    def _check_bandwidth_thresholds(self, dpid, port_no):
        if dpid not in self.port_stats or port_no not in self.port_stats[dpid]:
            self.logger.debug("No port stats for dpid %s port %s, skipping bandwidth check.", dpid, port_no)
            return
        port_data = self.port_stats[dpid][port_no]
        current_bw_mbps = port_data.get('bandwidth_mbps', 0.0)
        
        # Use configured values
        link_capacity_mbps = self.MAX_LINK_BANDWIDTH_MBPS 
        bundling_threshold_mbps = link_capacity_mbps * self.BUNDLING_THRESHOLD_PERCENT
        # unbundling_threshold_factor is used to calculate the trigger BW relative to a single link's capacity
        
        port_info = self.lacp_ports.get(dpid, {}).get(port_no)
        if not port_info:
            self.logger.debug("No LACP info for port %s on dpid %s, skipping bundling check.", port_no, dpid)
            return

        potential_lag_id = self.potential_lags.get(dpid, {}).get(port_no)
        active_lag_members = []
        if potential_lag_id and potential_lag_id in self.lags.get(dpid, {}):
            active_lag_members = self.lags[dpid][potential_lag_id]
        if port_no not in active_lag_members and potential_lag_id:
            if current_bw_mbps >= bundling_threshold_mbps:
                if not port_info.is_active():
                    self.logger.info("High bandwidth (%.2f Mbps >= %.2f Mbps) on dpid %s port %s. Activating LACP.",
                                    current_bw_mbps, bundling_threshold_mbps, dpid, port_no)
                    port_info.actor_state_activity = lacp.LACP_STATE_ACTIVE
            elif port_info.is_active() and current_bw_mbps < (bundling_threshold_mbps * 0.5):  # 50% of threshold
                if port_no not in active_lag_members:
                    self.logger.info("Low bandwidth (%.2f Mbps < %.2f Mbps) on dpid %s port %s. Deactivating LACP.",
                                    current_bw_mbps, bundling_threshold_mbps * 0.5, dpid, port_no)
                port_info.actor_state_activity = lacp.LACP_STATE_PASSIVE
        # Unbundling logic (simplified)
        elif port_no in active_lag_members and potential_lag_id:
            # Calculate total LAG bandwidth and capacity
            current_lag_bw_mbps = 0
            for member_port_no in active_lag_members:
                member_bw = self.port_stats.get(dpid, {}).get(member_port_no, {}).get('bandwidth_mbps', 0.0)
                current_lag_bw_mbps += member_bw

            unbundling_trigger_bw = link_capacity_mbps * self.UNBUNDLING_THRESHOLD_FACTOR # Use configured factor

            if current_lag_bw_mbps < unbundling_trigger_bw and len(active_lag_members) > 1 : # Only if LAG has more than 1 member
                self.logger.info("Low bandwidth (%.2f Mbps < %.2f Mbps) on LAG %s (dpid %s). Consider deactivating LACP for port %s.",
                                 current_lag_bw_mbps, unbundling_trigger_bw, potential_lag_id, dpid, port_no)
                # To simplify, we make this specific port passive. 
                # A more robust approach might involve a LAG-wide decision.
                port_info.actor_state_activity = lacp.LACP_STATE_PASSIVE # or 0
                port_info.actor_state_aggregation = 0
                port_info.actor_state_synchronization = 0
                port_info.actor_state_collecting = 0
                port_info.actor_state_distributing = 0
