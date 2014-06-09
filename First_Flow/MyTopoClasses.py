class match:
    def __init__(self, s_ip, d_ip):
        self.s_ip = s_ip
        self.d_ip = d_ip

class flow:
    def __init__(self, match, primary = [], secondary = [], path = [], start = None, byte_count = 0, active = True):
        self.flow_match = match
        self.primary_path = primary
        self.secondary_path = secondary
        self.used_path = path
        self.start = start
        self.byte_count = byte_count
        self.active = active

class switch:
    def __init__(self, dpid, ports = []):
        if not dpid:
            raise AssertionError("OpenFlowSwitch should have dpid")
        self.dpid = dpid
        self.ports = ports # list of active ports (that have connected links)

class port:
    def __init__(self, number, n_dpid, n_port_no):
        self.number = number
        self.neighbour_dpid = n_dpid
        self.neighbour_port_no = n_port_no

class link:
    def __init__(self, sw1, port1, sw2, port2, capacity = 10485760, link_cost = 0, cur_counter = 0, prev_counter = 0, last_load = 0):
        self.sw1 = sw1
        self.port1 = port1
        self.sw2 = sw2
        self.port2 = port2
        self.capacity = capacity # in Bytes, default is 10MByte per sec or 10.485.760 bytes 1Byte=8bits
        self.link_cost = link_cost # not currently used -> maybe set to ((load/10)/capacity)*100)
        self.cur_counter = cur_counter # byte counter for the current polling instance
        self.prev_counter = prev_counter # byte counter for the previous polling instance
        self.last_load=last_load # byte count measured during the last polling period
        # self.cashed_flrmv_count=

def toSubnet(ip):
    # only for /24 subnet. Transform an IP address to its /24 subnet.
    l = ip.split('.')
    l = ".".join(l[0:3])+'.0'
    return l
