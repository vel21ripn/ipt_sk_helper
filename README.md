# ipt_sk_helper

Helper for using cgroup for incoming traffic.

Limitation: works only for udp and tcp protocols.
Correctly handled icmp traffic related to open connections.
!!!
For icmp packet type ECHO/ECHO_REPLY cgroup definition does not work!
!!!

Compiling.

make && make modules_install

Usage:

modprobe ipt_sk_helper
sysctl net.ipv4.ip_early_demux=2

mkdir /sys/fs/cgroup/net_cls/testgroup2
echo 1234 >/sys/fs/cgroup/net_cls/testgroup2/net_cls.classid

iptables -A INPUT -m cgroup --cgroup 1234 -p icmp
iptables -A INPUT -m cgroup --cgroup 1234 -p udp
iptables -A INPUT -m cgroup --cgroup 1234 -p tcp
iptables -A OUTPUT -m cgroup --cgroup 1234 -p icmp
iptables -A OUTPUT -m cgroup --cgroup 1234 -p udp
iptables -A OUTPUT -m cgroup --cgroup 1234 -p tcp

echo $$ >/sys/fs/cgroup/net_cls/testgroup2/tasks

dig google.com
iptables -nvxL INPUT; iptables -nvxL OUTPUT
wget -4 -O /dev/zero https://google.com
iptables -nvxL INPUT; iptables -nvxL OUTPUT

