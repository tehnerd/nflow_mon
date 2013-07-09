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


def main():
    NF5 = nflowv5.NFLOWv5()
    IPF = ipfix.IPFIX()
    while True:
        packet = dsock.recv(9000)
        if(packet[1] == '\x05'):
            NF5.parse_packet(packet)
        elif(packet[1] == '\x0A'):
            IPF.parse_set(packet)

if __name__ == "__main__":
    main()
