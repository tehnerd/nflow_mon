first of all what it is not:
it's not a fullfeature netflow collector (for that purpose i highly recomends nfacct (www.pmacct.net))

this tool is a simple traffic/ddos anomaly analyzer.
right now it can be feeded by nflowv5 and ipfix.

how does it work:a
daemon listens udp packets on port 5000 (configurable; check nf_mon.py)
and each minutes calculates totall ammount of packets to the specefied IP address of intereset
(vip in term's of code) and compare it to the ammount, which was measured minute ago(baseline).
if totall_pkts > baseline*multiplier
then it calls send_notification function (coz it's very specific (sms/email/etc) - you must redefine it in separate
send_notification.py file)
and starts to collect more specific info about who sends what to this specific VIP
(src_ip, dst_ip (=vip), proto, dport, input_intf, agent(nflow border), and pps/bw)
after that it calls send_report_email func (must be redefined) and send all this info.

also  each minutes daemon sends to statsd info about packetrate to the specific VIP.

