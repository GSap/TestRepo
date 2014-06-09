"""
This module should look for active flow information every polling interval seconds and poll the switches that have active flows for flow
information.
This modules looks into the forwarding module to get info about active flows and into the topology module to get info
about the topology.
After receiving stat replies it updates the info in the topology.
It should handle, flowStatsRequest, flowStatReplies, flowRemoved messages.

MUST:


"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.recoco import Timer
from MyTopoClasses import *
from pox.lib.packet import *
from pox.lib.addresses import IPAddr, EthAddr
import time
import datetime

log = core.getLogger()

class Monitoring(object):

    _core_name = "monitoring"

    def __init__(self):
        core.current_topology.addListeners(self)
        # Initialize the attributes that represent the network topology/state.
        self.PolSwitches = [] # switches to be polled in every polling interval
        self.timestamp = time.time()
        self.pol_counter = 0
        self.pol_interval = 5 # polling interval in seconds

    def _handle_TopologyConverged(self, event):
        # when it catches an event that the topology has converged, it registers the listeners on how to handle the
        # openflow events. It means that it can start monitoring the network as the topology has converged
        # after bringing up the module for the first time.
        core.openflow.addListeners(self, priority = 10)
        log.debug("The Monitoring module STARTED...")
        Timer(self.pol_interval, self.SendFlowStatsReq, recurring=True)

    def _handle_FlowStatsReceived (self, event):
        # for every flow that the switch responded with stats, find the next hop link.
        # Increment current load counter for that link
        # Check if all polled switches have answered (if PolSwitches list is empty) and if yes, calculate load for
        # every link.
        dpid = dpid_to_str(event.connection.dpid)
        log.debug("FlowStatsReceived from: %s", dpid)

        for f in event.stats: # for future version this must be changed to receiving side writing because flow stats are for bytes received.
            for fl in core.forwarding.ActFlows:
                if str(f.match.nw_src) == fl.flow_match.s_ip and str(f.match.nw_dst) == fl.flow_match.d_ip and fl.active:
                    log.debug("Flow stats received for Active Flow from %s to %s subnet", str(f.match.nw_src), str(f.match.nw_dst))
                    # Find if the switch i received the stats from is egress node or not
                    for r in fl.used_path:
                        if dpid in r:
                            try:
                                sw1 = fl.used_path[fl.used_path.index(r)][0]
                                port1 = fl.used_path[fl.used_path.index(r)][1]
                                sw2 = fl.used_path[fl.used_path.index(r)+1][0]
                                # use mytopology method for update
                                core.current_topology.updateLinkCounters(byte_count = f.byte_count, sw1 = sw1, port1 = port1, sw2 = sw2)
                            except IndexError:
                                sw2 = None
                                log.debug("Node %s is an egress node for this flow. No need to increment any counters", dpid)

        # Removing dpid from PolSwitches since calculations were completed for flows from that switch
        if dpid in self.PolSwitches:
            log.debug("Calculations for flows from switch with dpid %s completed. Removing this switch from the PolSwitches list.", dpid)
            self.PolSwitches.remove(dpid)
        if not self.PolSwitches:
            log.debug("No more stats replies from switches pending. Calculating loads for polling interval.")
            ts = self.timestamp + (self.pol_counter * self.pol_interval)
            st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            core.current_topology.calculateLoads(st) # topology method
        else:
            log.debug("More responses from other switches remain to be processed")

    def _handle_FlowRemoved(self, event):
        # Update link load counters (remove total byte count received from previous link counter) and
        # cache value. Problem is when to remove the flow. byte_count i write in TM file is random, last one i received
        dpid = dpid_to_str(event.connection.dpid)
        srcip = str(event.ofp.match.nw_src)
        dstip = str(event.ofp.match.nw_dst)
        log.debug("FlowRemoved received from switch %s for flow %s to %s", dpid, srcip, dstip)
        ts = time.time()
        byte_count = event.ofp.byte_count
        duration = event.ofp.duration_sec
        timeout = event.ofp.idle_timeout
        start = ts-duration

        for fl in core.forwarding.ActFlows:
            if fl.flow_match.s_ip == srcip and fl.flow_match.d_ip == dstip: # don't check if active here, for sync issues as i remove multiple fl_rmvd messages
                for r in fl.used_path:
                    if dpid in r:
                        try:
                            sw1 = fl.used_path[fl.used_path.index(r)][0]
                            port1 = fl.used_path[fl.used_path.index(r)][1]
                            sw2 = fl.used_path[fl.used_path.index(r)+1][0]
                            core.current_topology.removeFlowBytes(event.ofp.byte_count, sw1, port1, sw2)
                        except IndexError:
                            sw2 = None
                            log.debug("Node %s is an egress node for this flow. No need to decrease any counters", dpid)

                            if event.idleTimeout is True:
                                stop = ts-timeout
                            else:
                                stop=ts
                            start_d = datetime.datetime.fromtimestamp(start).strftime('%Y-%m-%d %H:%M:%S')
                            stop_d = datetime.datetime.fromtimestamp(stop).strftime('%Y-%m-%d %H:%M:%S')
                            log.debug("Writing TM info to file. Opening file.")
                            f = open('TMInfo', 'a') # write load on file with timestamp
                            if int(stop-start) == 0: # or use try:
                                avg_flow_bw = byte_count
                            else:
                                avg_flow_bw = byte_count/int(stop-start) # only works if flow duration larger than 1sec
                            f.write(start_d+";"+stop_d+";"+srcip+";"+dstip+";"+str(byte_count)+";"+str(avg_flow_bw)+";\n")
                            log.debug("Finished writing to TM file")
                            f.close()
                return

    def SendFlowStatsReq(self):
        # Send flow stat requests to every switch that has active flows.

        del self.PolSwitches[:] # empty the plist of switches to be polled in order to calculate it again.

        # I must remove old link current values so that calculations are executed correctly when i get responses
        core.current_topology.resetLinkCounters()

        if core.forwarding.ActFlows:
            log.debug("Sending Flow Stat Requests to all switches that have active flows")
            # Here is where i should remove non-active flows
            core.forwarding.removeInactiveFlows()

            # log.debug("Before Sending Flow Stats messages the ActFlow list is:")
            for fl in core.forwarding.ActFlows:
                # print fl.flow_match.s_ip, fl.flow_match.d_ip, fl.used_path, fl.active
                for r in fl.used_path:
                    if (fl.used_path[fl.used_path.index(r)][0]) not in self.PolSwitches:
                        self.PolSwitches.append(fl.used_path[fl.used_path.index(r)][0])
        else:
            log.debug("No active flows at the moment, so not sending any flow stat requests")


        self.pol_counter+=1# increment polling session number

        if self.PolSwitches:
            for con in core.openflow.connections:
                if dpid_to_str(con.dpid) in self.PolSwitches:
                    log.debug("SendingFlowStatsRequest to %s: ", dpid_to_str(con.dpid))
                    msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
                    con.send(msg)

def launch ():
    if not core.hasComponent("monitoring"):
        core.registerNew(Monitoring)
