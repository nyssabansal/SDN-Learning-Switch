from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

# MAC to port table: { dpid: { mac: port } }
mac_to_port = {}

def _handle_PacketIn(event):
    packet = event.parsed
    dpid = event.connection.dpid
    in_port = event.port

    src = packet.src
    dst = packet.dst

    # Initialize table for this switch
    if dpid not in mac_to_port:
        mac_to_port[dpid] = {}

    # --- Learn MAC address ---
    if mac_to_port[dpid].get(src) != in_port:
        mac_to_port[dpid][src] = in_port
        log.info("LEARNED: Switch %s | MAC %s -> Port %s", dpid_to_str(dpid), src, in_port)
        _print_mac_table(dpid)

    # --- Forwarding logic ---
    if dst in mac_to_port[dpid]:
        out_port = mac_to_port[dpid][dst]
        log.info("FORWARDING: Switch %s | %s -> %s | In Port %s -> Out Port %s",
                 dpid_to_str(dpid), src, dst, in_port, out_port)

        # Install a flow rule
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, in_port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.data = event.ofp
        event.connection.send(msg)
        log.info("FLOW RULE INSTALLED: Switch %s | %s -> Port %s", dpid_to_str(dpid), dst, out_port)

    else:
        log.info("FLOODING: Switch %s | %s unknown, flooding all ports", dpid_to_str(dpid), dst)
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def _print_mac_table(dpid):
    """Print the MAC-to-port table in a formatted way."""
    log.info("")
    log.info("+===========================================+")
    log.info("|     MAC TABLE - Switch %-18s|", dpid_to_str(dpid))
    log.info("+=======================+===================+")
    log.info("| %-21s | %-17s |", "MAC Address", "Port")
    log.info("+=======================+===================+")
    for mac, port in mac_to_port[dpid].items():
        log.info("| %-21s | %-17s |", mac, port)
    log.info("+=======================+===================+")
    log.info("")

def _handle_ConnectionUp(event):
    log.info("Switch %s connected.", dpid_to_str(event.dpid))

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Custom Learning Switch Controller Running")
