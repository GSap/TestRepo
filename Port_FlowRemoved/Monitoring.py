"""
This module should look for active flow information every 10sec and poll the switches that have active flows for flow
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
        self.first_poll = True
        self.pol_counter = 0
        self.pol_interval = 5 # polling interval in seconds

    def _handle_TopologyConverged(self, event):
        # when it catches an event that the topology has converged, it registers the listeners on how to handle the
        # openflow events. It means that it can start monitoring the network as the topology has converged
        # after bringing up the module for the first time.
        core.openflow.addListeners(self, priority = 10)
        for con in core.openflow.connections: # init prev_counter for all links
            log.debug("Sending Port Stats Request to all switches for the first time: ")
            msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
            con.send(msg)
            self.PolSwitches.append(dpid_to_str(con.dpid))
        # log.debug("The Monitoring module STARTED...")
        # Timer(self.pol_interval, self.SendStatsReq, recurring=True)

    def _handle_PortStatsReceived (self, event):
        # for every port that the switch responded with stats, find the previous hop link.
        # Increment current load counter for that link with received bytes
        # Check if all polled switches have answered (if PolSwitches list is empty) and if yes, calculate load for
        # every link.
        dpid = dpid_to_str(event.connection.dpid)
        log.debug("Port Stats Received from: %s", dpid)

        for f in event.stats:
            # Find Link that i need to increment with rx_bytes
            sw2 = dpid
            port2 = f.port_no
            byte_count = f.rx_bytes # number of received bytes
            # use mytopology method to update counters
            core.current_topology.updateLinkCounters(sw = sw2, port = port2, byte_count = byte_count)

        # Removing dpid from PolSwitches since calculations were completed for ports from that switch
        if dpid in self.PolSwitches:
            log.debug("Calculations for ports from switch with dpid %s completed. Removing this switch from the PolSwitches list.", dpid)
            self.PolSwitches.remove(dpid)
        if not self.PolSwitches:
            if self.first_poll is True:
                self.first_poll = False
                log.debug("The Monitoring module STARTED...")
                Timer(self.pol_interval, self.SendStatsReq, recurring=True)
            else:
                log.debug("No more stats replies from switches pending. Calculating loads for polling interval.")
                ts = self.timestamp + (self.pol_counter * self.pol_interval)
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                core.current_topology.calculateLoads(st) # topology method
        else:
            log.debug("More responses from other switches remain to be processed")

    def _handle_FlowRemoved(self, event):
        # In case we have higher priority here we can set this method to update information in the ActFlows and have the
        # forwarding module to just delete the flow from the list.
        dpid = dpid_to_str(event.connection.dpid)
        srcip = str(event.ofp.match.nw_src)
        dstip = str(event.ofp.match.nw_dst)
        ts = time.time()
        byte_count = event.ofp.byte_count
        duration = event.ofp.duration_sec
        timeout = event.ofp.idle_timeout
        start = ts-duration

        log.debug("FlowRemoved received from %s for flow from %s to %s :", dpid, srcip, dstip)
        for flow in core.forwarding.ActFlows:
            if flow.flow_match.s_ip == srcip and flow.flow_match.d_ip == dstip and flow.active:
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
                break

    def SendStatsReq(self):
        # Send flow stat requests to every switch that has active flows.

        del self.PolSwitches[:] # empty the plist of switches to be polled in order to calculate it again.

        if core.forwarding.ActFlows:
            log.debug("Sending Port Stat Requests to all switches that have active flows")
            # Remove non-active flows in case they exist in the list
            core.forwarding.removeInactiveFlows()

            # log.debug("Before Sending Port Stats messages the ActFlow list is:")
            for fl in core.forwarding.ActFlows:
                # print fl.flow_match.s_ip, fl.flow_match.d_ip, fl.used_path, fl.active
                for r in fl.used_path:
                    if (fl.used_path[fl.used_path.index(r)][0]) not in self.PolSwitches:
                        self.PolSwitches.append(fl.used_path[fl.used_path.index(r)][0])
        else:
            log.debug("No active flows at the moment, so not sending any port stat requests")

        self.pol_counter+=1# increment polling session number

        if self.PolSwitches:
            for con in core.openflow.connections:
                if dpid_to_str(con.dpid) in self.PolSwitches:
                    log.debug("Sending Port Stats Request to %s: ", dpid_to_str(con.dpid))
                    msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
                    con.send(msg)

def launch ():
    if not core.hasComponent("monitoring"):
        core.registerNew(Monitoring)
