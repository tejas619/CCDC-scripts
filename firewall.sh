#!/bin/bash/
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -A INPUT -p tcp --dport 22 -s 10.128.$3.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED, RELATED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED, RELATED -j ACCEPT
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -j DROP
