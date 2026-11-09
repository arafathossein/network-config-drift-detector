# 2026-11-02 02:00:01 by RouterOS 7.16.1
# software id = 8KQ2-4TZM
#
# model = CCR2004-16G-2S+
# serial number = HFA09K7C2R1
/interface bridge add name=bridge-lan
/interface list add name=WAN
/interface list add name=LAN
/interface list member add interface=ether1 list=WAN
/interface list member add interface=bridge-lan list=LAN
/ip address add address=10.20.0.1/24 interface=bridge-lan network=10.20.0.0
/ip address add address=203.0.113.10/29 interface=ether1 network=203.0.113.8
/ip route add disabled=no dst-address=0.0.0.0/0 gateway=203.0.113.9
/ip firewall filter add action=accept chain=input connection-state=established,related
/ip firewall filter add action=accept chain=input in-interface-list=LAN
/ip firewall filter add action=drop chain=input in-interface-list=WAN
/ip firewall filter add action=accept chain=forward connection-state=established,related
/ip firewall filter add action=drop chain=forward connection-state=invalid
/ip firewall filter add action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN
/ip firewall nat add action=masquerade chain=srcnat out-interface-list=WAN
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set ssh address=10.20.0.0/24
/ip service set winbox address=10.20.0.0/24
/snmp community set [ find default=yes ] addresses=10.20.0.50/32 name=nms-ro-7f3k
/system identity set name=edge-rtr-01
/system logging action add name=remote remote=10.20.0.50 target=remote
/system logging add action=remote topics=info
/system logging add action=remote topics=warning
/user add group=full name=netadmin
