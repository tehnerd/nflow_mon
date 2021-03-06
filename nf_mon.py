#!/usr/bin/python

import gevent.socket as socket
from multiprocessing import Process
import report_handler
import cPickle as pickle
import gevent
import redis
import datetime
import json

try:
    from send_notification import send_notification
except ImportError:
    def send_notification(ip, ratio):
        print("possible ddos on %s with over baseline ratio %s"
             %(ip,ratio,))

import sys
import struct
import ipfix
import nflowv5
import os


def daemonize():
    pid = os.fork()
    if pid != 0:
        exit(0)
    os.setsid()
    fd = open("/dev/null","r+")
    os.dup2(sys.stdin.fileno(),fd.fileno())
    os.dup2(sys.stdout.fileno(),fd.fileno())
    os.dup2(sys.stderr.fileno(),fd.fileno())

#dictionary initialazing

DAEMON_PORT  = 5000
DAEMON_IP = '0.0.0.0'
SAMPLING_RATE = 2000

def init_nflow_dicts(vips_file, vips_pps, vips_flags, vips_baseline, 
                     vips_multiplier, vips_map):
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

def clear_pps(vips_pps):
    for key in vips_pps:
        vips_pps[key] = 0

def collect_flow(dsock, NF5, IPF, vips_flags, vips_pps,
                 ddos_records, other_records):
    while True:
        packet, agent = dsock.recvfrom(9000)
        flow_list = list()
        ddos_list = list()
        other_list = list()
        if(packet[1] == '\x05'):
            flow_list, ddos_list = NF5.parse_packet(packet, 
                                                    agent[0], vips_flags)
        elif(packet[1] == '\x0A'):
            flow_list, ddos_list, other_list = IPF.parse_set(packet, agent[0], vips_flags)
        if flow_list:
            for flow in flow_list:
                if flow[0] in vips_pps:
                    if flow[2] > 100000:
                        continue
                    else:
                        vips_pps[flow[0]] += (flow[2]*SAMPLING_RATE)
        if other_list:
            other_records.extend(other_list)
        if ddos_list:
            ddos_records.extend(ddos_list)

def collect_reports():
    rdb = redis.Redis()
    queue = rdb.pubsub()
    queue.subscribe('ddos_reports')
    for report in queue.listen():
        try:
            report = pickle.loads(report['data'])
            report_handler.report_handler(report)
        except Exception, e :
            continue



def analyze_stats(rdb, ddos_records, other_records, vips_flags, vips_pps,
                  vips_baseline, vips_multiplier, vips_map):
    gevent.sleep(60)
    if ddos_records:
        rdb.publish('ddos_reports', pickle.dumps(ddos_records))
        for key in vips_flags:
            if vips_flags[key] == 1:
                vips_flags[key] = 0
        del ddos_records[:]
    if other_records:
        rdb.publish('internal_traffic', pickle.dumps(other_records))
        del other_records[:]
    for key in vips_pps:
        if vips_pps[key] != 0:
            #nfmon_gauge.send('pps_'+vips_map[key].replace('.','-'),vips_pps[key])
            if vips_baseline[key] != 0:
                # we dont care about services with pps < 10kpps
                if(vips_pps[key] > 60000 and 
                   vips_pps[key] > vips_baseline[key]*vips_multiplier[key]):
                    ratio = vips_pps[key]//vips_baseline[key]
                    vips_flags[key] = 1
                    send_notification(vips_map[key],ratio)
            vips_baseline[key] = vips_pps[key]
    clear_pps(vips_pps)

def main():
    if not len(sys.argv) > 1:
        print("cant find file with mapping")
        print("usage: nf_mon <file/w/mapping>")
        sys.exit(-1)
    try:
        vips_file = open(sys.argv[1],"r")
    except:
        sys.exit("cant open file")
    

    #define  datastructures
    vips_pps = dict()
    vips_baseline = dict()
    vips_multiplier = dict()
    vips_map = dict()
    vips_flags = dict()
    ddos_records = list()
    other_records = list()
    init_nflow_dicts(vips_file, vips_pps, vips_flags, vips_baseline, 
                     vips_multiplier, vips_map)
    daemonize()
    report_process = Process(target=collect_reports)
    report_process.start()
    
    #socket's init
    dsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    dsock.bind((DAEMON_IP, DAEMON_PORT))
    rdb = redis.Redis()

    #nflov5 and ipfix contexts
    NF5 = nflowv5.NFLOWv5()
    IPF = ipfix.IPFIX()

    gevent.spawn(collect_flow, dsock, NF5, IPF, vips_flags, vips_pps,
                 ddos_records, other_records)
    while True:
        analyze_job = gevent.spawn(analyze_stats, rdb, ddos_records,
                                   other_records,
                                   vips_flags, vips_pps, 
                                   vips_baseline, vips_multiplier,
                                   vips_map)
        gevent.joinall([analyze_job])
    report_process.join()

if __name__ == "__main__":
    main()
