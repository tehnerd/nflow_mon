import struct
class IPFIX(object):

    def __init__(self):
        self._header_fmt = "!HHIII"
        self._set_hdr_fmt = "!HH"
        self._tmplt_hdr_fmt = "!HH"
        self._fld_spec_fmt_ietf = "!HH"
        self._fld_spec_fmt_ent = "!HHI"
        self.ipfix_dict = {
"1":"octetDeltaCount",
"43":"RESERVED",
"2":"packetDeltaCount",
"44":"sourceIPv4Prefix",
"3":"RESERVED",
"45":"destinationIPv4Prefix",
"4":"protocolIdentifier",
"46":"mplsTopLabelType",
"5":"ipClassOfService",
"47":"mplsTopLabelIPv4Address",
"6":"tcpControlBits",
"48-51":"RESERVED",
"7":"sourceTransportPort",
"52":"minimumTTL",
"8":"sourceIPv4Address",
"53":"maximumTTL",
"9":"sourceIPv4PrefixLength",
"54":"fragmentIdentification",
"10":"ingressInterface",
"55":"postIpClassOfService",
"11":"destinationTransportPort",
"56":"sourceMacAddress",
"12":"destinationIPv4Address",
"57":"postDestinationMacAddress",
"13":"destinationIPv4PrefixLength",
"58":"vlanId",
"14":"egressInterface",
"59":"postVlanId",
"15":"ipNextHopIPv4Address",
"60":"ipVersion",
"16":"bgpSourceAsNumber",
"61":"flowDirection",
"17":"bgpDestinationAsNumber",
"62":"ipNextHopIPv6Address",
"18":"bgpNexthopIPv4Address",
"63":"bgpNexthopIPv6Address",
"19":"postMCastPacketDeltaCount",
"64":"ipv6ExtensionHeaders",
"20":"postMCastOctetDeltaCount",
"65-69":"RESERVED",
"21":"flowEndSysUpTime",
"70":"mplsTopLabelStackSection",
"22":"flowStartSysUpTime",
"71":"mplsLabelStackSection2",
"23":"postOctetDeltaCount",
"72":"mplsLabelStackSection3",
"24":"postPacketDeltaCount",
"73":"mplsLabelStackSection4",
"25":"minimumIpTotalLength",
"74":"mplsLabelStackSection5",
"26":"maximumIpTotalLength",
"75":"mplsLabelStackSection6",
"27":"sourceIPv6Address",
"76":"mplsLabelStackSection7",
"28":"destinationIPv6Address",
"77":"mplsLabelStackSection8",
"29":"sourceIPv6PrefixLength",
"78":"mplsLabelStackSection9",
"30":"destinationIPv6PrefixLength",
"79":"mplsLabelStackSection10",
"31":"flowLabelIPv6",
"80":"destinationMacAddress",
"32":"icmpTypeCodeIPv4",
"81":"postSourceMacAddress",
"33":"igmpType",
"34":"RESERVED",
"85":"octetTotalCount",
"35":"RESERVED",
"86":"packetTotalCount",
"36":"flowActiveTimeout",
"87":"RESERVED",
"37":"flowIdleTimeout",
"88":"fragmentOffset",
"38":"RESERVED",
"89":"RESERVED",
"39":"RESERVED",
"90":"mplsVpnRouteDistinguisher",
"40":"exportedOctetTotalCount",
"41":"exportedMessageTotalCount",
"42":"exportedFlowRecordTotalCount",
"128":"bgpNextAdjacentAsNumber",
"169":"destinationIPv6Prefix",
"129":"bgpPrevAdjacentAsNumber",
"170":"sourceIPv6Prefix",
"130":"exporterIPv4Address",
"171":"postOctetTotalCount",
"131":"exporterIPv6Address",
"172":"postPacketTotalCount",
"132":"droppedOctetDeltaCount",
"173":"flowKeyIndicator",
"133":"droppedPacketDeltaCount",
"174":"postMCastPacketTotalCount",
"134":"droppedOctetTotalCount",
"175":"postMCastOctetTotalCount",
"135":"droppedPacketTotalCount",
"176":"icmpTypeIPv4",
"136":"flowEndReason",
"177":"icmpCodeIPv4",
"137":"commonPropertiesId",
"178":"icmpTypeIPv6",
"138":"observationPointId",
"179":"icmpCodeIPv6",
"139":"icmpTypeCodeIPv6",
"180":"udpSourcePort",
"140":"mplsTopLabelIPv6Address",
"181":"udpDestinationPort",
"141":"lineCardId",
"182":"tcpSourcePort",
"142":"portId",
"183":"tcpDestinationPort",
"143":"meteringProcessId",
"184":"tcpSequenceNumber",
"144":"exportingProcessId",
"185":"tcpAcknowledgementNumber",
"145":"templateId",
"186":"tcpWindowSize",
"146":"wlanChannelId",
"187":"tcpUrgentPointer",
"147":"wlanSSID",
"188":"tcpHeaderLength",
"148":"flowId",
"189":"ipHeaderLength",
"149":"observationDomainId",
"190":"totalLengthIPv4",
"150":"flowStartSeconds",
"191":"payloadLengthIPv6",
"151":"flowEndSeconds",
"192":"ipTTL",
"152":"flowStartMilliseconds",
"193":"nextHeaderIPv6",
"153":"flowEndMilliseconds",
"194":"mplsPayloadLength",
"154":"flowStartMicroseconds",
"195":"ipDiffServCodePoint",
"155":"flowEndMicroseconds",
"196":"ipPrecedence",
"156":"flowStartNanoseconds",
"197":"fragmentFlags",
"157":"flowEndNanoseconds",
"198":"octetDeltaSumOfSquares",
"158":"flowStartDeltaMicroseconds",
"199":"octetTotalSumOfSquares",
"159":"flowEndDeltaMicroseconds",
"200":"mplsTopLabelTTL",
"160":"systemInitTimeMilliseconds",
"201":"mplsLabelStackLength",
"161":"flowDurationMilliseconds",
"202":"mplsLabelStackDepth",
"162":"flowDurationMicroseconds",
"203":"mplsTopLabelExp",
"163":"observedFlowTotalCount",
"204":"ipPayloadLength",
"164":"ignoredPacketTotalCount",
"205":"udpMessageLength",
"165":"ignoredOctetTotalCount",
"206":"isMulticast",
"166":"notSentFlowTotalCount",
"207":"ipv4IHL",
"167":"notSentPacketTotalCount",
"208":"ipv4Options",
"168":"notSentOctetTotalCount",
"209":"tcpOptions",
"210":"paddingOctets",
"218":"tcpSynTotalCount",
"211":"collectorIPv4Address",
"219":"tcpFinTotalCount",
"212":"collectorIPv6Address",
"220":"tcpRstTotalCount",
"213":"exportInterface",
"221":"tcpPshTotalCount",
"214":"exportProtocolVersion",
"222":"tcpAckTotalCount",
"215":"exportTransportProtocol",
"223":"tcpUrgTotalCount",
"216":"collectorTransportPort",
"224":"ipTotalLength",
"217":"exporterTransportPort",
"237":"postMplsTopLabelExp",
"238":"tcpWindowScale",
        }
        self.format_dict = {
        "1":"B",
        "2":"H",
        "4":"I",
        "8":"Q",
        "16":"2Q",
        }
        self.template_dict = dict()
        self.template_len_dict = dict()
        self.ordinary_fields = dict()
        self.extended_fields = dict()
    def parse_header(self, packet):
        return struct.unpack(self._header_fmt, packet[0:16])

    def parse_tmplt_set(self, packet, agent):
        tmplt_record = struct.unpack(self._tmplt_hdr_fmt,packet[20:24])
        tmplt_id = tmplt_record[0]
        self.template_dict[agent][tmplt_id] = "!"
        self.template_len_dict[agent][tmplt_id] = 0
        self.ordinary_fields[agent][tmplt_id] = list()
        self.extended_fields[agent][tmplt_id] = list()
        tmplt_fields_count = tmplt_record[1]
        fld_cntr = 1
        packet = packet[24:]
        while fld_cntr <= tmplt_fields_count:
            fld_spec_id = struct.unpack("!H",packet[0:2])[0]
            if ((fld_spec_id >> 15) == 0):
                fld = struct.unpack(self._fld_spec_fmt_ietf,packet[0:4])
                self.template_dict[agent][tmplt_id]+=self.format_dict[str(fld[1])]
                self.template_len_dict[agent][tmplt_id]+=fld[1]
                if(self.ipfix_dict[str(fld[0])] == "destinationIPv4Address" or
                   self.ipfix_dict[str(fld[0])] == "destinationIPv6Address" or
                   self.ipfix_dict[str(fld[0])] == "octetDeltaCount" or
                   self.ipfix_dict[str(fld[0])] == "packetDeltaCount"):
                    self.ordinary_fields[agent][tmplt_id].append(fld_cntr-1)
                    self.extended_fields[agent][tmplt_id].append(fld_cntr-1)
                if(self.ipfix_dict[str(fld[0])] == "sourceIPv4Address" or
                   self.ipfix_dict[str(fld[0])] == "protocolIdentifier" or
                   self.ipfix_dict[str(fld[0])] == "sourceTransportPort" or
                   self.ipfix_dict[str(fld[0])] == "destinationTransportPort" or
                   self.ipfix_dict[str(fld[0])] == "ingressInterface"): 
                    self.extended_fields[agent][tmplt_id].append(fld_cntr-1)
                fld_cntr += 1
                packet = packet[4:]
            else:
                packet = packet[8:]
                fld_cntr += 1
    def parse_data_set(self,packet, set_hdr, agent, flag_dict):
        tmplt_struct = self.template_dict[agent][set_hdr[0]]
        set_len = set_hdr[1]
        tmplt_len = self.template_len_dict[agent][set_hdr[0]]
        offset = 20
        flow_list = list()
        ddos_list = list()
        while offset < set_len:
            flow_record = struct.unpack(tmplt_struct,
                                        packet[offset:offset + tmplt_len])
            ordinary_record = [flow_record[cntr] for cntr
                               in self.ordinary_fields[agent][set_hdr[0]]]
            if(flag_dict and ordinary_record[0] in flag_dict and
               flag_dict[ordinary_record[0]] == 1):
                extended_record = [flow_record[cntr] for cntr
                               in self.extended_fields[agent][set_hdr[0]]]
                extended_record.append(agent)
                ddos_list.append(extended_record)
            offset += tmplt_len
            flow_list.append(ordinary_record)
        return flow_list, ddos_list
           

    def parse_set(self, packet, agent, flag_dict = None):
        if not agent in self.template_dict:
            self.template_dict[agent] = dict()
            self.template_len_dict[agent] = dict()
            self.ordinary_fields[agent] = dict()
            self.extended_fields[agent] = dict()
        set_hdr = struct.unpack(self._set_hdr_fmt, packet[16:20])
        if (set_hdr[0] == 2):
            self.parse_tmplt_set(packet, agent)
            return None, None
        if(set_hdr[0] in self.template_dict[agent]):
            return self.parse_data_set(packet, set_hdr, agent, flag_dict)
        return None, None



