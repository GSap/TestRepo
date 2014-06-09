"""
This module installs forwarding rules to openflow switches based on traffic characteristics.
It checks the flows IPv4 source and destination subnet, calculates the path that this traffic should take
and pushes the respective flow entries to the switches on the path.

v0.2
----
2 pre-calculated paths exist for source/destination pairs, the primary and the secondary.
The forwarding decision is made as follows:
1. If a link between 2 nodes on the primary path is down then the secondary path is chosen. OK
2. For every new incoming flow the primary path is first considered. If the
load on every link on the primary path is less or equal to 50% during the previous polling, then this path is used. Otherwise
 if one link on the primary path is loaded over 50% then the secondary path is used. In case of a tie breaker, the
 path with the least loaded link is chosen. OK

MUST:


LOOK INTO:


FUTURE:
Add listeners for topology change events. On topology change event recalculate paths for flows that are affected
and send Flow Mods again.

CalculatePath(): Every link has a cost equal to its' load. So a 50% loaded link has cost of 50.
The algorithm returns the path that has the highest cost in any link up to a maximum cost of 50.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.packet import *
from MyTopoClasses import *
import time, datetime

log = core.getLogger()

class MyForwarding (object):

    _core_name = "forwarding"

    def __init__(self):
        core.current_topology.addListeners(self)
        # Initialize the attributes that represent the network topology/state.
        # self.idletimeout = 15
        self.ActFlows = [] # list of flows that are currently active in our network (soft and hard timeouts not expired)
        self.Paths = [] # list of possible paths per flow. This would probably get dynamically filled by a forwarding
                        # decision mechanism that looks into topology to get information about how nodes are connected.

        temp_match = match("192.168.1.0", "192.168.2.0")
        prim = [("00-00-00-00-00-05",2), ("00-00-00-00-00-06",1)] # Primary path of switches the flow goes through in order
        sec = [("00-00-00-00-00-05",3), ("00-00-00-00-00-07",3), ("00-00-00-00-00-08",3), ("00-00-00-00-00-06",1)] # Secondary path of switches the flow goes through in order
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.1.0", "192.168.3.0")
        prim = [("00-00-00-00-00-05",3), ("00-00-00-00-00-07",1)]
        sec = [("00-00-00-00-00-05",2), ("00-00-00-00-00-06",3), ("00-00-00-00-00-08",2), ("00-00-00-00-00-07",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.1.0", "192.168.4.0")
        prim = [("00-00-00-00-00-05",2), ("00-00-00-00-00-06",3), ("00-00-00-00-00-08",1)]
        sec = [("00-00-00-00-00-05",3), ("00-00-00-00-00-07",3), ("00-00-00-00-00-08",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.2.0", "192.168.1.0")
        prim = [("00-00-00-00-00-06",2), ("00-00-00-00-00-05",1)]
        sec = [("00-00-00-00-00-06",3), ("00-00-00-00-00-08",2), ("00-00-00-00-00-07",2), ("00-00-00-00-00-05",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.2.0", "192.168.3.0")
        prim = [("00-00-00-00-00-06",3), ("00-00-00-00-00-08",2), ("00-00-00-00-00-07",1)]
        sec = [("00-00-00-00-00-06",2), ("00-00-00-00-00-05",3), ("00-00-00-00-00-07",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.2.0", "192.168.4.0")
        prim = [("00-00-00-00-00-06",3), ("00-00-00-00-00-08",1)]
        sec = [("00-00-00-00-00-06",2), ("00-00-00-00-00-05",3), ("00-00-00-00-00-07",3), ("00-00-00-00-00-08",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.3.0", "192.168.1.0")
        prim = [("00-00-00-00-00-07",2), ("00-00-00-00-00-05",1)]
        sec = [("00-00-00-00-00-07",3), ("00-00-00-00-00-08",3), ("00-00-00-00-00-06",2), ("00-00-00-00-00-05",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.3.0", "192.168.2.0")
        prim = [("00-00-00-00-00-07",2), ("00-00-00-00-00-05",2), ("00-00-00-00-00-06",1)]
        sec = [("00-00-00-00-00-07",3), ("00-00-00-00-00-08",3), ("00-00-00-00-00-06",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.3.0", "192.168.4.0")
        prim = [("00-00-00-00-00-07",3), ("00-00-00-00-00-08",1)]
        sec = [("00-00-00-00-00-07",2), ("00-00-00-00-00-05",2), ("00-00-00-00-00-06",3), ("00-00-00-00-00-08",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.4.0", "192.168.1.0")
        prim = [("00-00-00-00-00-08",2), ("00-00-00-00-00-07",2), ("00-00-00-00-00-05",1)]
        sec = [("00-00-00-00-00-08",3), ("00-00-00-00-00-06",2), ("00-00-00-00-00-05",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.4.0", "192.168.2.0")
        prim = [("00-00-00-00-00-08",3), ("00-00-00-00-00-06",1)]
        sec = [("00-00-00-00-00-08",2), ("00-00-00-00-00-07",2), ("00-00-00-00-00-05",2), ("00-00-00-00-00-06",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

        temp_match = match("192.168.4.0", "192.168.3.0")
        prim = [("00-00-00-00-00-08",2), ("00-00-00-00-00-07",1)]
        sec = [("00-00-00-00-00-08",3), ("00-00-00-00-00-06",2), ("00-00-00-00-00-05",3), ("00-00-00-00-00-07",1)]
        temp_flow = flow(temp_match, primary=prim, secondary=sec)
        self.Paths.append(temp_flow)

    def _handle_TopologyConverged(self, event):
        # when it catches an event that the topology has converged, it registers the listeners on how to handle the
        # openflow events. It means that it can start making forwarding decisions as the topology has converged
        # after bringing up the module for the first time.
        core.openflow.addListeners(self)
        log.debug("The Forwarding module STARTED...")

    def _handle_PacketIn (self, event):
        # monitor active flows: add flow to active flow list
        # send flow modification messages for new flows or re-transmit rules for already received packet_ins

        dpid = dpid_to_str(event.connection.dpid)
        inport = event.port
        packet = event.parsed

        # buffer_id of the switch where this packet is buffered
        # if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
        bid = event.ofp.buffer_id

        if not packet.parsed:
          log.warning("%i %i ignoring unparsed packet", dpid, inport)
          return

        if isinstance(packet.next, ipv4):
            srcip = str(packet.next.srcip)
            dstip = str(packet.next.dstip)

            log.debug("Received Packet_in from %s for flow from %s to %s: ", dpid, srcip, dstip)

            # Find a way to fix the bug with duplicate packet_ins. Track ActFlows
            # I receive duplicate packets because the ping request reaches the second switch in the path before
            # the flow mod message does.
            already_exists = None # Flow that i received packet_in active or not
            if self.ActFlows:
                for af in self.ActFlows:
                    if toSubnet(srcip) == af.flow_match.s_ip and toSubnet(dstip) == af.flow_match.d_ip and af.active:
                        log.debug("Flow already in the list of Active flows - Won't add it again ")
                        already_exists = True
                        break
                if already_exists is None:
                    log.debug("Flow not active: Appending this flow to Active flows")
                    temp_match = match(toSubnet(srcip), toSubnet(dstip))
                    # self.CalculatePath should return the active path for that flow.
                    act_path = self.CalculatePath(temp_match)
                    # Handle case of both paths being down
                    if act_path is None:
                        log.debug("There is no possible path for this flow at them moment. All paths are broken. Not activating flow.")
                    else:
                        # timestamp
                        ts = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
                        temp_flow = flow(temp_match, path = act_path, start = ts, active = True)
                        self.ActFlows.append(temp_flow)
                        log.debug("Flow added to the Active Flow list.")
            else:
                log.debug("No Active Flow at the moment. Adding flow from %s to %s in Active flows", toSubnet(srcip), toSubnet(dstip))
                temp_match = match(toSubnet(srcip), toSubnet(dstip))
                act_path = self.CalculatePath(temp_match)
                if act_path is None:
                    log.debug("There is no possible path for this flow at them moment. All paths are broken. Not activating flow.")
                else:
                    # ts = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
                    ts = time.time()
                    temp_flow = flow(temp_match, path = act_path, start = ts, active = True)
                    self.ActFlows.append(temp_flow)
                    log.debug("Flow added to the Active Flow list.")

            if already_exists is not None:
                # search info about the path of this flow.
                # send rule about how to forward traffic only to the switch that sent the packet_in.
                log.debug("Sending Flow Mod only to %s for this flow", dpid)
                out_port = self.retrievePort(srcip, dstip, dpid)
                self.sendForwardingRule(srcip, dstip, bid, out_port, event.connection.dpid)
            else:
                # find info about all the switches in the path of this flow.
                # set up path by sending rule to all switches in the path.
                log.debug("Sending Flow Mod to all switches in the path for this flow")
                self.setUpPath(srcip, dstip, bid, event.connection.dpid)

    def _handle_FlowRemoved (self, event):
        # monitor active flows: deactivate flow in active flow list
        dpid = dpid_to_str(event.connection.dpid)
        srcip = str(event.ofp.match.nw_src)
        dstip = str(event.ofp.match.nw_dst)

        log.debug("FlowRemoved received from %s for flow from %s to %s :", dpid, srcip, dstip)

        for flow in self.ActFlows:
            if flow.flow_match.s_ip == srcip and flow.flow_match.d_ip == dstip and flow.active:
                log.debug("Found flow from %s to %s that has to be removed from Active flows list", srcip, dstip)
                self.ActFlows.remove(flow)
                log.debug("Flow removed from Active Flows list")
                break

    def removeInactiveFlows(self):
        # method called by monitoring module to remove all inactive flows
        for f in self.ActFlows:
            if f.active is None:
                log.debug("Removing Inactive Flow")
                self.ActFlows.remove(f)

    def retrievePort(self, srcip, dstip, dpid):
        # method that retrieves the output port for a flow for a switch
        for af in self.ActFlows: # find the flow in active flows
            if toSubnet(srcip) == af.flow_match.s_ip and toSubnet(dstip) == af.flow_match.d_ip and af.active:
                for p in af.used_path: # find the switch in the path
                    if dpid in p:
                        try:
                            outPort = af.used_path[af.used_path.index(p)][1] # find output port
                            return outPort
                        except IndexError:
                            log.debug("Couldn't find output port due to index error.")
                            outPort = None
                            return outPort

    def sendForwardingRule(self, srcip, dstip, bid, out_port, dpid):
        # method that sends packet to one switch only, flow removed only by the first switch.
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = toSubnet(srcip)+"/24"
        msg.match.nw_dst = toSubnet(dstip)+"/24"
        msg.idle_timeout = 8
        for af in self.ActFlows: # find the flow in active flows
            if msg.match.nw_src == af.flow_match.s_ip and msg.match.nw_dst == af.flow_match.d_ip and af.active:
                if dpid_to_str(dpid) in af.used_path[0]:# af.used_path[-1]: --> or last switch
                    msg.flags = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
                    break
        msg.buffer_id = bid
        msg.actions.append(of.ofp_action_output(port = out_port))
        core.openflow.sendToDPID(dpid, msg)

    def setUpPath(self, srcip, dstip, bid, dpid):
        # method that sets up the forwarding path for a new incoming flow, flow removed only by the last switch.
        for af in self.ActFlows: # find the flow in active flows
            if toSubnet(srcip) == af.flow_match.s_ip and toSubnet(dstip) == af.flow_match.d_ip and af.active:
                for con in core.openflow.connections: # for every switch on the path of the flow
                    for p in af.used_path: # find the switch in the path
                        if dpid_to_str(con.dpid) in p:
                            try:
                                outPort = af.used_path[af.used_path.index(p)][1] # find output port
                            except IndexError:
                                log.debug("Couldn't find output port due to index error.")
                                outPort = None
                            msg = of.ofp_flow_mod()
                            msg.match.dl_type = 0x0800
                            msg.match.nw_src = toSubnet(srcip)+"/24"
                            msg.match.nw_dst = toSubnet(dstip)+"/24"
                            msg.idle_timeout = 8
                            # log.debug("Sending Flow Mod message to %s with attributes: ", dpid_to_str(con.dpid))
                            # log.debug("Source: %s, Destination: %s", msg.match.nw_src, msg.match.nw_dst)
                            if af.used_path.index(p) == 0: # len(af.used_path)-1: --> for last switch
                                msg.flags = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
                            if con.dpid == dpid: # add buffer_id to apply the flow rule immediately for the switch that sent the packetIN
                                msg.buffer_id = bid
                            # log.debug("BufferID: %s", str(msg.buffer_id))
                            msg.actions.append(of.ofp_action_output(port = outPort))
                            # log.debug("Output Port: %i", outPort)
                            con.send(msg)
                return

    def CalculatePath(self, temp_match):
        # method that calculates the path that must be used to forward traffic for this flow
        # search inside the path list and choose primary or backup
        for p in self.Paths: # find the path for this flow
            if p.flow_match.s_ip == temp_match.s_ip and p.flow_match.d_ip == temp_match.d_ip:
                # for every link in the primary path check first if the link exists. Then get the link load
                # and keep the highest link load value
                prim_cost = 0
                for it in p.primary_path:
                    sw1 = p.primary_path[p.primary_path.index(it)][0] # find switch1 of the link
                    port1 = p.primary_path[p.primary_path.index(it)][1] # find port1 of the link
                    try:
                        sw2 = p.primary_path[p.primary_path.index(it)+1][0] # find switch2 of the link
                        # use MyTopology method to get cost for that link
                        # check or change link from dpid to string in MyTopology or use str_to_dpid
                        tmp = core.current_topology.getLinkCost(sw1 = str_to_dpid(sw1), port1 = port1, sw2 = str_to_dpid(sw2))
                        if tmp is None:
                            log.debug("Primary path is broken.")
                            prim_cost = None
                            break
                        if tmp > prim_cost:
                            prim_cost = tmp
                    except IndexError:
                        pass
                        # log.debug("Node is an egress node for this flow. This is a link to the host - not calculating.")
                if (prim_cost is None) or (prim_cost > 50): # MUST change to 50% of capacity value here
                    # for every link in the secondary path check the link load and keep the highest link load value
                    sec_cost = 0
                    for it in p.secondary_path:
                        sw1 = p.secondary_path[p.secondary_path.index(it)][0] # find switch1 of the link
                        port1 = p.secondary_path[p.secondary_path.index(it)][1] # find port1 of the link
                        try:
                            sw2 = p.secondary_path[p.secondary_path.index(it)+1][0] # find switch2 of the link
                            tmp = core.current_topology.getLinkCost(sw1 = str_to_dpid(sw1), port1 = port1, sw2 = str_to_dpid(sw2))
                            if tmp is None:
                                  log.debug("Secondary path is broken.")
                                  sec_cost = None
                                  break
                            if tmp > sec_cost:
                                  sec_cost = tmp
                        except IndexError:
                            pass
                            #log.debug("Node is an egress node for this flow. This is a link to the host - not calculating.")
                    # Choose the path that is not broken or the lowest of the values kept
                    if (prim_cost is not None) and (sec_cost is not None): # if both paths are not broken
                        if sec_cost < prim_cost: # return the one with the less loaded link on its path
                            log.debug("Secondary Path less loaded. Forwarding via this one.")
                            return p.secondary_path
                        else:
                            log.debug("Primary Path less loaded. Forwarding via this one.")
                            return p.primary_path
                    elif (prim_cost is not None) and (sec_cost is None): # else if secondary path is broken, return primary irrespective of load
                        log.debug("Secondary Path is broken. Forwarding via Primary.")
                        return p.primary_path
                    elif (prim_cost is None) and (sec_cost is not None): # else if primary path is broken, return secondary irrespective of load
                        log.debug("Primary Path is broken. Forwarding via Secondary.")
                        return p.secondary_path
                    elif (prim_cost is None) and (sec_cost is None): # else if both paths are broken, return None
                        log.debug("Both Paths are broken. Doing nothing and letting packets drop.")
                        return None
                else:
                    log.debug("Using primary path as it is loaded less than 50%.")
                    return p.primary_path # if primary link not broken and loaded less than 50%

    # def _handle_TopologyChange(self, event):
    #     # when it catches an event that the topology has changes, it checks the active flows and if an active flow is
    #     # affected by thischange it recalculate the path for this flow and send new flow modification messages to the
    #     # openflow switches.
    #
    #     changed_link = event.link
    #     changed_dpid = event.dpid
    #     switch_added = event.switch_added
    #     switch_removed = event.switch_removed
    #     link_added = event.link_added
    #     link_removed = event.link_removed
    #
    #     if link_removed is not None:
    #         # find if any active flow is affected and for this flow recalculate path and send new instructions.
    #         log.debug("Forwarding module was told that a link went down.")
    #         sw1, sw2 = changed_link.sw1, changed_link.sw2
    #         p1, p2 = changed_link.port1, changed_link.port2
    #         # Look in the ActFlows list and if a flow path is using this link then send a flow mod (delete) message to
    #         # all switches for that flow. No need to do anything about the FlowRemoved mesage that will get generated
    #         # as it won't find any link to take any actions on
    #
    #     if link_added is not None:
    #         # doing nothing for now. We might want to recalculate paths and if one is better send new instructions.
    #         log.debug("Forwarding module was told that a link went up.")
    #         pass
    #     if switch_added is not None:
    #         # doing nothing for now. We might want to recalculate paths and if one is better sene new instructions.
    #         log.debug("Forwarding module was told that a switch was added.")
    #         pass
    #     if switch_removed is not None:
    #         # find if any active flow is affected and for this flow recalculate path and send new instructions.
    #         log.debug("Forwarding module was told that a switch was removed.")
    #         pass

def launch ():
    if not core.hasComponent("forwarding"):
        core.registerNew(MyForwarding)
