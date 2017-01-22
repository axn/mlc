#!/bin/bash
# set -ex

# Copyright (c) 2011  Axel Neumann
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA


# WARNING: 
# This package requires root priveleges and may have bugs that format your hard disk!!!!
# Use on your own risk! It is highly recommended to use provided scripts 
# ONLY in a completely isolated environment like qmp or virtual box


if [ -f ./mlc-vars.sh ] ; then
    . ./mlc-vars.sh
else
    echo "could not find mlc-vars.sh in $(pwd)"; exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "This script should be run as 'root'"; exit 1
fi 


if [ "$(id -u)" != "0" ]; then
    echo "This script should be run as 'root'"
    exit 1
fi 

modprobe ip6_tunnel
#modprobe niit

MLC_setup_bridge $mlc_net0_link $mlc_ip4_admin_gateway $mlc_net0_ip4_mask $mlc_net0_ip4_brc
MLC_setup_bridge $mlc_net1_link 
MLC_setup_bridge $mlc_net2_link 
MLC_setup_bridge $mlc_net3_link 

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.route.max_size=100000

sysctl -w fs.inotify.max_user_instances=1024  # 1024  # orig 128
sysctl -w fs.inotify.max_user_watches=65526   # 65536 # orig 8192
sysctl -w fs.inotify.max_queued_events=131072 # 131072 #orig 16384

sysctl -w net.ipv4.neigh.default.gc_thresh1=4096  # orig 128 # 4096
sysctl -w net.ipv4.neigh.default.gc_thresh2=8192  # orig 256 # 8192
sysctl -w net.ipv4.neigh.default.gc_thresh3=16384 # orig 512 # 16384

sysctl -w net.ipv6.neigh.default.gc_thresh1=4096  # orig 128 # 4096
sysctl -w net.ipv6.neigh.default.gc_thresh2=8192  # orig 256 # 8192
sysctl -w net.ipv6.neigh.default.gc_thresh3=16384 # orig 512 # 16384

iptables_mask=$(ipcalc -b $mlc_ip4_admin_gateway/$mlc_ip4_admin_netmask | grep Network: | awk '{print $2}')


for dev in eth0 wlan0; do
	if ! iptables -t nat -L -nv | grep MASQUERADE | grep $dev | grep $iptables_mask ; then
	    iptables -t nat -I POSTROUTING -s $iptables_mask -o $dev -j MASQUERADE
	fi
done

if ! mount | grep cgroup; then
	mkdir -p /cgroup
	mount -t cgroup none /cgroup
	# echo "none /cgroup cgroup defaults 0 0" >> /etc/fstab
fi


lxc-checkconfig  # anything enabled?!!


#mlc_net_force_reset
#mlc_veth_force_cleanup
mlc_net_flush
mlc_cpu_max

# dpkg -r mlocate     # <-  I did this
# please somebody tell me how the new upstart-job scripts work and how to reliable disable updatedb and other stuff
/etc/init.d/cron stop      #
/etc/init.d/anachron stop  #
#mkdir -p /etc/cron.d 
#echo "* * * * *     root /bin/echo \"\`/bin/date\` minutely\" >> /root/mlc-error.log" > /etc/cron.d/mlc
#echo "#!/bin/sh" > /etc/cron.hourly/mlc; chmod uog+x /etc/cron.hourly/mlc
#echo "/bin/echo \"\`/bin/date\` hourly\" >> /root/mlc-error.log" >> /etc/cron.hourly/mlc

/etc/init.d/munin-node stop # stop munin-node # service munin-node stop
/etc/init.d/smokeping stop
/etc/init.d/apport stop

echo "WARNING! Disabled cron, munin, smokeping, ... services to prevent casual cpu load."
echo " Reenable them after mlc usage!"

lxc-start -n $mlc_name_prefix$mlc_mother_id -d



