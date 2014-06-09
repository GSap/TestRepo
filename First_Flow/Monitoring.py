"""
This module should look for active flow information every polling period seconds and polls the first switch on the path of active flows
for flow information in regard to link loads and also receives flow removed info from the first switch for the TM.
This modules looks into the forwarding module to get info about active flows and into the topology module to get info
about the topology.
After receiving stat replies it updates the info in the topology. It increments the link load of every link in the path
of the flow by the number of flow bytes it received from the 1st switch in the path of that flow.
It should handle, flowStatsRequest, flowStatReplies, flowRemoved messages.
It also creates a TM representation in a file that can be later parsed to gain historic TM data.

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
        core.openflow.addListeners(self, priority = 10) # set higher priority for this, default is 0
        log.debug("The Monitoring module STARTED...")
        Timer(self.pol_interval, self.SendFlowStatsReq, recurring=True)

    def _handle_FlowStatsReceived (self, event):
        # for every flow that the switch responded with stats increment all links in the path with the load value.
        # Check if all polled switches have answered (if PolSwitches list is empty) and if yes, calculate load for
        # every link.
        dpid = dpid_to_str(event.connection.dpid)
        log.debug("FlowStatsReceived from: %s", dpid)

        for f in event.stats:
            for fl in core.forwarding.ActFlows:
                if str(f.match.nw_src) == fl.flow_match.s_ip and str(f.match.nw_dst) == fl.flow_match.d_ip and fl.active:
                    log.debug("Flow stats received for Active Flow from %s to %s subnet", str(f.match.nw_src), str(f.match.nw_dst))
                    if fl.used_path[0][0] == dpid: # check if this it the first switch for this flow
                        fl.byte_count = f.byte_count # save the current flow byte count
                        for r in fl.used_path:
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
            # I must remove old link current values so that calculations are executed correctly in the next polling
            core.current_topology.resetLinkCounters()
        else:
            log.debug("More responses from other switches remain to be processed")

    def _handle_FlowRemoved(self, event):
        # Update link load counters (remove total byte count received from previous link counter) and
        # cache value. MUST: set higher priority here
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
            if fl.flow_match.s_ip == srcip and fl.flow_match.d_ip == dstip and fl.active:
                if event.idleTimeout is True:
                    stop = ts-timeout
                    start_d = datetime.datetime.fromtimestamp(start).strftime('%Y-%m-%d %H:%M:%S')
                    stop_d = datetime.datetime.fromtimestamp(stop).strftime('%Y-%m-%d %H:%M:%S')
                    log.debug("Opening file")
                    f = open('TMInfo', 'a') # write flow info on file with timestamp
                    log.debug("Writing Flow info to TM file")
                    # if reason timeout: start=ts-duration, stop=ts-timeout, avg=byte_count/stop-start
                    # else: start=ts-duration, stop=ts, avg=byte_count/stop-start
                    # avg_flow_bw = byte_count/((int(ts)-int(fl.start))-int(timeout))
                    if int(stop-start) == 0: # or use try:
                        avg_flow_bw = byte_count
                    else:
                        avg_flow_bw = byte_count/int(stop-start) # only works if flow duration larger than 1sec
                    f.write(start_d+";"+stop_d+";"+srcip+";"+dstip+";"+str(byte_count)+";"+str(avg_flow_bw)+";\n")
                    log.debug("Finished writing to TM file")
                    f.close()
                    for r in fl.used_path:
                        try:
                            sw1 = fl.used_path[fl.used_path.index(r)][0]
                            port1 = fl.used_path[fl.used_path.index(r)][1]
                            sw2 = fl.used_path[fl.used_path.index(r)+1][0]
                            core.current_topology.removeFlowBytes(byte_count, sw1, port1, sw2)
                        except IndexError:
                            sw2 = None
                            log.debug("Node %s is an egress node for this flow. No need to decrease any counters", dpid)
                else:
                    inc = byte_count-fl.byte_count
                    stop=ts
                    start_d = datetime.datetime.fromtimestamp(start).strftime('%Y-%m-%d %H:%M:%S')
                    stop_d = datetime.datetime.fromtimestamp(stop).strftime('%Y-%m-%d %H:%M:%S')
                    log.debug("Opening file")
                    f = open('TMInfo', 'a') # write flow info on file with timestamp
                    log.debug("Writing Flow info to TM file")
                    # if reason timeout: start=ts-duration, stop=ts-timeout, avg=byte_count/stop-start
                    # else: start=ts-duration, stop=ts, avg=byte_count/stop-start
                    # avg_flow_bw = byte_count/((int(ts)-int(fl.start))-int(timeout))
                    if int(stop-start) == 0: # or use try:
                        avg_flow_bw = byte_count
                    else:
                        avg_flow_bw = byte_count/int(stop-start) # only works if flow duration larger than 1sec
                    f.write(start_d+";"+stop_d+";"+srcip+";"+dstip+";"+str(byte_count)+";"+str(avg_flow_bw)+";\n")
                    log.debug("Finished writing to TM file")
                    f.close()
                    for r in fl.used_path:
                        try:
                            sw1 = fl.used_path[fl.used_path.index(r)][0]
                            port1 = fl.used_path[fl.used_path.index(r)][1]
                            sw2 = fl.used_path[fl.used_path.index(r)+1][0]
                            core.current_topology.updateLinkCounters(inc, sw1, port1, sw2)
                            core.current_topology.removeFlowBytes(fl.byte_count, sw1, port1, sw2)
                        except IndexError:
                            sw2 = None
                            log.debug("Node %s is an egress node for this flow. No need to decrease any counters", dpid)

    def SendFlowStatsReq(self):
        # Send flow stat requests to the first switch in the path of every active flow.

        del self.PolSwitches[:] # empty the plist of switches to be polled in order to calculate it again.

        if core.forwarding.ActFlows:
            log.debug("Sending Flow Stat Request to the first switch in the path of every active flow.")
            # Here is where i should remove non-active flows
            core.forwarding.removeInactiveFlows()

            # log.debug("Before Sending Flow Stats messages the ActFlow list is:")
            for fl in core.forwarding.ActFlows:
                # print fl.flow_match.s_ip, fl.flow_match.d_ip, fl.used_path, fl.active
                if (fl.used_path[0][0]) not in self.PolSwitches:
                    self.PolSwitches.append(fl.used_path[0][0])
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
