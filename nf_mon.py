#!/usr/bin/python

import socket
import sys
import struct
import ipfix
import nflowv5

DAEMON_PORT  = 5000
DAEMON_IP = '0.0.0.0'
dsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
dsock.bind((DAEMON_IP, DAEMON_PORT))

vips_bw = dict()
vips_map = dict()

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
    for key in vips_bw.keys()
        vips_bw[key] = 0

def main():
    NF5 = nflowv5.NFLOWv5()
    IPF = ipfix.IPFIX()
    while True:
        packet, agent = dsock.recvfrom(9000)
        if(packet[1] == '\x05'):
            NF5.parse_packet(packet, agent[0])
        elif(packet[1] == '\x0A'):
            IPF.parse_set(packet, agent[0])

if __name__ == "__main__":
    main()
