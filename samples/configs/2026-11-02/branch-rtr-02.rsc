# 2026-11-02 02:00:04 by RouterOS 7.16.1
# software id = 3MXR-81QD
#
# model = RB5009UG+S+
# serial number = HFB12P4D9K2
/interface bridge add name=bridge-lan
/ip address add address=10.21.0.1/24 interface=bridge-lan network=10.21.0.0
/ip address add address=203.0.113.42/29 interface=ether1 network=203.0.113.40
/ip route add dst-address=0.0.0.0/0 gateway=203.0.113.41
/ip firewall filter add action=accept chain=input connection-state=established,related
/ip firewall filter add action=accept chain=input src-address=10.21.0.0/24
/ip firewall filter add action=drop chain=input
/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/system identity set name=branch-rtr-02
/user add group=full name=netadmin
