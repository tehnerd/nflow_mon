#!/usr/bin/python

import gevent.socket as socket
import gevent
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


vips_bw = dict()
vips_map = dict()
cntr = dict()
cntr[1] = 0

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
    vip_net = socket.inet_aton(vip)
    vip_int = struct.unpack('!L',vip_net)[0]
    vips_bw[vip_int] = 0
    vips_map[vip_int] = vip

def clear_bw():
    for key in vips_bw.keys():
        vips_bw[key] = 0
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
                if flow[0] in vips_bw:
                    vips_bw[flow[0]] += flow[1]
        cntr[1] += 1



def print_stats():
    gevent.sleep(60)
    print(cntr[1]/60)
    cntr[1] = 0
    clear_bw()

def main():
    gevent.spawn(collect_flow)
    while True:
        analyze_job = gevent.spawn(print_stats)
        gevent.joinall([analyze_job])

if __name__ == "__main__":
    main()
