import struct
import socket

class NFLOWv5(object):
    def __init__(self):
        """
        Bytes   Contents    Description
        0-1 version NetFlow export format version number
        2-3 count   Number of flows exported in this packet (1-30)
        4-7 sys_uptime  Current time in milliseconds since the export device booted
        8-11    unix_secs   Current count of seconds since 0000 UTC 1970
        12-15   unix_nsecs  Residual nanoseconds since 0000 UTC 1970
        16-19   flow_sequence   Sequence counter of total flows seen
        20  engine_type Type of flow-switching engine
        21  engine_id   Slot number of the flow-switching engine
        22-23   sampling_interval   First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
        """
        self._header_fmt = "!HHIIIIBBH"
        """
        Flow record format
        Bytes   Contents    Description
        0-3 srcaddr Source IP address
        4-7 dstaddr Destination IP address
        8-11    nexthop IP address of next hop router
        12-13   input   SNMP index of input interface
        14-15   output  SNMP index of output interface
        16-19   dPkts   Packets in the flow
        20-23   dOctets Total number of Layer 3 bytes in the packets of the flow
        24-27   first   SysUptime at start of flow
        28-31   last    SysUptime at the time the last packet of the flow was received
        32-33   srcport TCP/UDP source port number or equivalent
        34-35   dstport TCP/UDP destination port number or equivalent
        36  pad1    Unused (zero) bytes
        37  tcp_flags   Cumulative OR of TCP flags
        38  prot    IP protocol type (for example, TCP = 6; UDP = 17)
        39  tos IP type of service (ToS)
        40-41   src_as  Autonomous system number of the source, either origin or peer
        42-43   dst_as  Autonomous system number of the destination, either origin or peer
        44  src_mask    Source address prefix mask bits
        45  dst_mask    Destination address prefix mask bits
        46-47   pad2    Unused (zero) bytes
        """
        self._flow_fmt = "!IIIHHIIIIHHBBBBHHBBH"

    def parse_header(self, packet):
        return struct.unpack(self._header_fmt,packet[0:24])

    def parse_packet(self, packet, agent):
        header = self.parse_header(packet)
        flow_count = header[1]
        flow = 1
        flow_list = list()
        ddos_list = list()
        while flow <= flow_count:
            flow_record = struct.unpack(self._flow_fmt,packet[24*flow:24*flow+48])
            flow_list.append([flow_record[1],flow_record[6], flow_record[5]])
            flow += 1
        return flow_list, ddos_list
