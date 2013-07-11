#!/usr/bin/python

import gevent.socket as socket
import gevent
import statsd
import sys
import struct
import ipfix
import nflowv5

DAEMON_PORT  = 5000
DAEMON_IP = '0.0.0.0'
dsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
dsock.bind((DAEMON_IP, DAEMON_PORT))
NF5 = nflowv5.NFLOWv5()
IPF = ipfix.IPFIX()
SAMPLING_RATE = 2000
nfmon_gauge = statsd.Gauge('netflow_mon_pps')

vips_pps = dict()
vips_baseline = dict()
vips_multiplyer = dict()
vips_map = dict()
cntr = dict()

if not len(sys.argv) > 1:
    print("cant find file with mapping")
    print("usage: nf_mon <file/w/mapping>")
    sys.exit(-1)

try:
    vips_file = open(sys.argv[1],"r")
except:
    sys.exit("cant open file")

for vip in vips_file:
    vip = vip.strip()
    vip = vip.split()
    if len(vip) != 2:
        sys.exit("vips file must be in format <vip> -- <baseline>")
    vip_net = socket.inet_aton(vip[0])
    vip_int = struct.unpack('!L',vip_net)[0]
    vips_pps[vip_int] = 0
    vips_baseline[vip_int] = 0
    vips_multiplyer[vip_int] = int(vip[1])
    vips_map[vip_int] = vip[0]

def clear_bw():
    for key in vips_pps.keys():
        vips_pps[key] = 0

def collect_flow():
    while True:
        packet, agent = dsock.recvfrom(9000)
        flow_list = list()
        if(packet[1] == '\x05'):
            flow_list = NF5.parse_packet(packet, agent[0])
        elif(packet[1] == '\x0A'):
            flow_list = IPF.parse_set(packet, agent[0])
        if flow_list:
            for flow in flow_list:
                if flow[0] in vips_pps:
                    vips_pps[flow[0]] += (flow[2]*SAMPLING_RATE)


def analyze_stats():
    gevent.sleep(60)
    for key in vips_pps.keys():
        if vips_pps[key] != 0:
            nfmon_gauge.send('pps_'+vips_map[key].replace('.','-'),vips_pps[key])
            if vips_baseline[key] != 0:
                if vips_pps[key] > 10000 and 
                   vips_pps[key] > vips_baseline[key]*vips_multiplyer[key]:
                    print("possible ddos on %s"%(vips_map[key],))
            vips_baseline[key] = vips_pps[key]
    clear_bw()

def main():
    gevent.spawn(collect_flow)
    while True:
        analyze_job = gevent.spawn(analyze_stats)
        gevent.joinall([analyze_job])

if __name__ == "__main__":
    main()
