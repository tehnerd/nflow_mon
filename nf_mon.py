#!/usr/bin/python

import gevent.socket as socket
from multiprocessing import Process
import cPickle as pickle
import gevent
import statsd
import redis
import sys
import struct
import ipfix
import nflowv5

#dictionary initialazing
vips_pps = dict()
vips_baseline = dict()
vips_multiplier = dict()
vips_map = dict()
vips_flags = dict()
ddos_records = list()



DAEMON_PORT  = 5000
DAEMON_IP = '0.0.0.0'
dsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
dsock.bind((DAEMON_IP, DAEMON_PORT))
NF5 = nflowv5.NFLOWv5()
IPF = ipfix.IPFIX()
SAMPLING_RATE = 2000
nfmon_gauge = statsd.Gauge('netflow_mon_pps')
rdb = redis.StrictRedis()

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
    vips_flags[vip_int] = 0
    vips_baseline[vip_int] = 0
    vips_multiplier[vip_int] = int(vip[1])
    vips_map[vip_int] = vip[0]

def clear_bw():
    for key in vips_pps.keys():
        vips_pps[key] = 0

def collect_flow():
    while True:
        packet, agent = dsock.recvfrom(9000)
        flow_list = list()
        ddos_list = list()
        if(packet[1] == '\x05'):
            flow_list, ddos_list = NF5.parse_packet(packet, 
                                                    agent[0], vips_flags)
        elif(packet[1] == '\x0A'):
            flow_list, ddos_list = IPF.parse_set(packet, agent[0], vips_flags)
        if flow_list:
            for flow in flow_list:
                if flow[0] in vips_pps:
                    vips_pps[flow[0]] += (flow[2]*SAMPLING_RATE)
        if ddos_list:
            ddos_records.append(ddos_list)

def parse_reports():
    rdb = redis.StrictRedis()
    queue = rdb.pubsub()
    queue.subscribe('ddos_reports')
    for report in queue.listen():
        try:
            for line in pickle.loads(report['data']):
                print(line)
        except:
            print(report['data'])

def analyze_stats():
    gevent.sleep(60)
    if ddos_records:
        rdb.publish('ddos_reports', pickle.dumps(ddos_records))
        for key in vips_flags.keys():
            if vips_flags[key] == 1:
                vips_flags[key] = 0
        del ddos_records[:]
    for key in vips_pps.keys():
        if vips_pps[key] != 0:
            nfmon_gauge.send('pps_'+vips_map[key].replace('.','-'),vips_pps[key])
            if vips_baseline[key] != 0:
                if(vips_pps[key] > 1 and 
                   vips_pps[key] > vips_baseline[key]*vips_multiplier[key]):
                    ratio = vips_pps[key]//vips_baseline[key]
                    vips_flags[key] = 1
                    print("possible ddos on %s with over baseline ratio %s"
                         %(vips_map[key],ratio,))
            vips_baseline[key] = vips_pps[key]
    clear_bw()

def main():
    report_process = Process(target=parse_reports)
    report_process.start()
    gevent.spawn(collect_flow)
    while True:
        analyze_job = gevent.spawn(analyze_stats)
        gevent.joinall([analyze_job])
    report_process.join()

if __name__ == "__main__":
    main()
