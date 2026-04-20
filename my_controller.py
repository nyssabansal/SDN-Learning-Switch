from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

# MAC to port table: { dpid: { mac: port } }
mac_to_port = {}

# Track already-installed flow rules to avoid duplicate logs
installed_flows = set()

def _handle_PacketIn(event):
    packet = event.parsed
    dpid = event.connection.dpid
    in_port = event.port

    src = packet.src
    dst = packet.dst

    # Initialize table for this switch
    if dpid not in mac_to_port:
        mac_to_port[dpid] = {}

    # --- Learn MAC address (only log if NEW) ---
    if mac_to_port[dpid].get(src) != in_port:
        mac_to_port[dpid][src] = in_port
        log.info("NEW MAC LEARNED: %s is on Port %s", src, in_port)
        _print_mac_table(dpid)

    # --- Forwarding logic ---
    if dst in mac_to_port[dpid]:
        out_port = mac_to_port[dpid][dst]

        # Only show path and install rule if not done before
        flow_key = (dpid, str(src), str(dst), in_port)
        if flow_key not in installed_flows:
            installed_flows.add(flow_key)
            _print_path(dpid, src, dst, in_port, out_port)

            # Install forwarding rule on switch
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, in_port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data = event.ofp
            event.connection.send(msg)
            log.info("RULE INSTALLED: %s -> %s via Port %s", src, dst, out_port)
        else:
            # Rule already installed, switch handles it — no need to log
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, in_port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data = event.ofp
            event.connection.send(msg)

    else:
        # Only log flood once per unknown destination
        flood_key = (dpid, str(dst))
        if flood_key not in installed_flows:
            installed_flows.add(flood_key)
            log.info("UNKNOWN DEST: %s not in table, flooding all ports", dst)

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def _print_path(dpid, src, dst, in_port, out_port):
    log.info("")
    log.info("+--------------------------------------------------+")
    log.info("|                  PATH TAKEN                      |")
    log.info("+--------------------------------------------------+")
    log.info("|  From  : %-40s|", src)
    log.info("|  To    : %-40s|", dst)
    log.info("|  Path  : Port %-3s --> [Switch] --> Port %-8s|", in_port, out_port)
    log.info("+--------------------------------------------------+")
    log.info("")

def _print_mac_table(dpid):
    log.info("")
    log.info("+================================+")
    log.info("|  MAC TABLE - Switch %-10s|", dpid_to_str(dpid))
    log.info("+==================+============+")
    log.info("| %-16s | %-10s |", "MAC Address", "Port")
    log.info("+==================+============+")
    for mac, port in mac_to_port[dpid].items():
        log.info("| %-16s | %-10s |", mac, port)
    log.info("+==================+============+")
    log.info("")

def _handle_ConnectionUp(event):
    log.info("Switch %s connected.", dpid_to_str(event.dpid))

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Custom Learning Switch Controller Running")
