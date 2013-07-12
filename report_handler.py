import socket
import operator
import struct
try:
    from send_notification import send_report_email
except ImportError:
    def send_report_email(a,b):
        pass

"""
report in format of 
[line, line, line ... ]
each line contains:
<src_ip> <dst_ip> <proto> <sport> <dport> <input_intf> <bw> <pps> <agent>
"""
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack('!L',ip_int))
def report_handler(report):
    report_dict_pps = dict()
    report_dict_bw = dict()
    sorted_report_pps = list()
    sorted_report_bw = list()
    for line in report:
        # we will aggegate by:
        #src_ip, dst_ip, proto, dport, input_intf, agent
        if (line[0],line[1],line[2],line[4],line[5],line[8]) in report_dict_pps:
            report_dict_pps[line[0],line[1],line[2],
                            line[4],line[5],line[8]] += line[7]
            report_dict_bw[line[0],line[1],line[2],
                           line[4],line[5],line[8]] += line[6]   
        else:
            report_dict_pps[line[0],line[1],line[2],
                            line[4],line[5],line[8]] = line[7]
            report_dict_bw[line[0],line[1],line[2],
                           line[4],line[5],line[8]] = line[6]   
    report_list = sorted(report_dict_pps.iteritems(),
                               key=operator.itemgetter(1))[-100:]
    for line in report_list:
        sorted_report_pps.append((int_to_ip(line[0][0]),
                                 int_to_ip(line[0][1]),
                                 line[0][3],
                                 line[0][4],
                                 line[0][5],
                                 line[1]))

    report_list = sorted(report_dict_bw.iteritems(),
                               key=operator.itemgetter(1))[-100:]
    for line in report_list:
        sorted_report_bw.append((int_to_ip(line[0][0]),
                                 int_to_ip(line[0][1]),
                                 line[0][3],
                                 line[0][4],
                                 line[0][5],
                                 line[1]))

    send_report_email(sorted_report_pps,sorted_report_bw)

