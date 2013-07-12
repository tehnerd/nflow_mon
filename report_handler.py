import socket
import operator

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

    sorted_pps_report = sorted(report_dict_pps.iteritems(),
                               key=operator.itemgetter(1))
    sorted_bw_report = sorted(report_dict_bw.iteritems(),
                               key=operator.itemgetter(1))
    print(sorted_pps_report)
