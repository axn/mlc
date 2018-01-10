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


mlc_lxc_bin_dir="$(which lxc-create | awk -F'/lxc-create' '{print $1}')"
mlc_lxc_examples="/usr/share/doc/lxc/examples"

mlc_path_dir="$(pwd)"
mlc_tmp_dir="$(pwd)/tmp"
mlc_known_hosts_file="$mlc_tmp_dir/known_hosts"
mlc_veth_cache="$mlc_tmp_dir/mlc_veth_cache.txt"

mlc_ssh="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$mlc_known_hosts_file -o ConnectTimeout=1 "

mkdir -p $mlc_tmp_dir

#mlc_conf_dir="/usr/local/var/lib/lxc"
mlc_conf_dir="/var/lib/lxc"

mlc_owrt_fs_tgz="/usr/src/openwrt/13f/qmpfw-gsoc.git/build/alix/bin/x86/openwrt-x86-generic-rootfs.tar.gz"

mlc_arch="i386" # i386 (for i686)  or  amd64 (for x86_64), or nothing for autodetection
mlc_debian_suite="stretch" # squeeze, lenny, wheezy, sid.  Or check whats available on: http://cdn.debian.net/debian/

mlc_empty_dirs=
mlc_copy_dirs=
mlc_mount_dirs=

#mlc_empty_dirs="media dev mnt proc sys   var/local var/lock var/log var/log/fsck var/mail var/opt var/run var/tmp"
#mlc_copy_dirs="etc home root selinux srv tmp var/spool var/www "
#mlc_mount_dirs="bin boot lib opt sbin usr  var/backups var/cache var/lib"

mlc_empty_dirs="dev media mnt opt proc run run/mount sys var/backups var/local var/log var/mail "
mlc_copy_dirs="etc home root selinux srv tmp lib64 var/lock var/run var/spool var/tmp var/www "
mlc_mount_dirs="sbin bin usr boot lib var/cache var/lib "


mlc_name_prefix="mlc"
mlc_bridge_prefix="mbr"
mlc_p2p_bridge_prefix="M"
mlc_p2p_bridge_delimiter="="
mlc_p2p_bridge_idx_delimiter="_"

mlc_veth_prefix="veth"
mlc_dev_prefix="eth"

mlc_mnt="NULL"

mlc_mother_id="0002"

mlc_min_node="1000"
mlc_max_node="8999"

mlc_peer_idx_min="4"
mlc_peer_idx_max="7"

mlc_ns3_idx_min="3"
mlc_ns3_idx_max="3"

mlc_mac6_multicast="33:33:0:0:0:0/ff:ff:0:0:0:0"

mlc_pub_key="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAvbTSxpSlDBV7m+c0i1rUFpaasegLjRL+BZunrpKb1YFvJXwS2DD1WqnAypBk/AlgR9KQlXfHSpeRqxY0HbBnPWG79LQ2NlVlcvF7xokpw3eUeYKpJwx0ivNd/koKE3wvoFN158JseFhUBGcZdaFRGh6bFhrvvXYmAHjroHvaGgVR8YQI4DiKrBULQd75p/U3G2UjeZpMeTK+LaCkuWh0g+93LQPp21w6v8hOZtudJ2rhNHNYB0oFJF8Uf5q+uVjpbOzA/nPxs/qiF4zdg2oyj0eAi0Yfo+eSVI/zj3iyeC4rF5S8/s/cyet+XMXvLQ6X12XUYu7Qv/VEVwI5QkVqSw== mlc@mlc"

mlc_passwd="mlc"

mlc_cpu_idle_assumption=50

mlc_lang="en_US.UTF-8"
mlc_language="en_US:en"
export LANG="$mlc_lang"
export LANGUAGE="$mlc_language"
export LC_ALL="$mlc_lang"


mlc_mac_prefix="a0:cd:ef"
mlc_net_mtu="1500"

mlc_dns="8.8.4.4"
mlc_node="22"

mlc_ip4_prefix0="10"
mlc_admin_idx="0"

mlc_ip4_admin_prefix1="000"
mlc_ip4_admin_netmask="255.224.0.0"
mlc_ip4_admin_netmask="255.255.0.0"
mlc_ip4_admin_broadcast="10.031.255.255"
mlc_ip4_admin_gateway="10.0.0.1"

mlc_ip4_ula1_prefix1="100"
mlc_ip4_ula1_netmask="255.224.0.0"
mlc_ip4_ula1_broadcast="10.127.255.255"

mlc_ip4_ula2_prefix1="200"
mlc_ip4_ula2_netmask="255.224.0.0"
mlc_ip4_ula2_broadcast="10.223.255.255"

mlc_ip4_ula3_prefix1="050"
mlc_ip4_ula3_netmask="255.224.0.0"
mlc_ip4_ula3_broadcast="10.63.255.255"



mlc_ip6_prefix="1"
mlc_ip6_ripe1_prefix="2011:0:0"
mlc_ip6_ripe2_prefix="2012:0:0"
mlc_ip6_ripe3_prefix="2013:0:0"
mlc_ip6_ula1_prefix="fd01:0:0"
mlc_ip6_ula2_prefix="fd02:0:0"
mlc_ip6_ula3_prefix="fd03:0:0"


MLC_ip6_ula() {
  local ula48_prefix=$1
  local mac=$2
  local ula32_host=$3
  local mac1="$(( 16#$( echo $mac | awk -F':' '{print $1}' ) ))"
  local mac2="$(( 16#$( echo $mac | awk -F':' '{print $2}' ) ))"
  local mac3="$(( 16#$( echo $mac | awk -F':' '{print $3}' ) ))"
  local mac4="$(( 16#$( echo $mac | awk -F':' '{print $4}' ) ))"
  local mac5="$(( 16#$( echo $mac | awk -F':' '{print $5}' ) ))"
  local mac6="$(( 16#$( echo $mac | awk -F':' '{print $6}' ) ))"
 
  printf "%s:%X:%X:%X::%s\n" $ula48_prefix $(( ( $mac1 * 256 ) + $mac2 ))  $(( ( $mac3 * 256 ) + $mac4 ))  $(( ( $mac5 * 256 ) + $mac6 )) $ula32_host
}


MLC_calc_veth_name() {
  local node=$1
  local idx=$2
  local name="${mlc_name_prefix}${node}"

  echo "${mlc_veth_prefix}${node}_${idx}"
}


MLC_calc_mac() {
    local node=$1
    local idx=$2

    local node_div100="$(( $node / 100 ))"
    local node_mod100="$(( $node % 100 ))"

    echo "${mlc_mac_prefix}:${node_div100}:${node_mod100}:${idx}"
}

MLC_calc_ip4() {
    local prefix1=$1
    local node=$2
    local idx=$3

    local node_div100="$(( $node / 100 ))"
    local node_mod100="$(( $node % 100 ))"

    echo "${mlc_ip4_prefix0}.$(( prefix1 + $idx )).${node_div100}.${node_mod100}"
}

MLC_assign_networks() {
    local idx
    
    mlc_node=$1

# Control/Admin Network:
    idx="$mlc_admin_idx"
    mlc_net0_link="${mlc_bridge_prefix}${idx}"
    mlc_net0_name="${mlc_dev_prefix}${idx}"
    mlc_net0_mtu="1500"
    mlc_net0_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net0_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net0_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_admin_prefix1 $mlc_node $idx )"
    mlc_net0_ip4_mask="$mlc_ip4_admin_netmask"
    mlc_net0_ip4_brc="$mlc_ip4_admin_broadcast"
    mlc_net0_ip4_gw="$mlc_ip4_admin_gateway"


# Mesh Networks:
    idx="1"
    mlc_net1_link="${mlc_bridge_prefix}${idx}"
    mlc_net1_name="${mlc_dev_prefix}${idx}"
    mlc_net1_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net1_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net11_name="eth${idx}.11"
    mlc_net11_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net11_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net11_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net11_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net1_mac 1)"
    mlc_net11_ula_mask="48"
    mlc_net11_rip_addr="$mlc_ip6_ripe1_prefix:$mlc_node::11"
    mlc_net11_rip_mask="128"

    mlc_net12_name="eth${idx}.12"
    mlc_net12_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net12_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net12_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net12_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net1_mac 1)"
    mlc_net12_ula_mask="48"
    mlc_net12_rip_addr="$mlc_ip6_ripe2_prefix:$mlc_node::12"
    mlc_net12_rip_mask="128"

    mlc_net13_name="eth${idx}.13"
    mlc_net13_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula3_prefix1 $mlc_node $idx )" 
    mlc_net13_ip4_mask="$mlc_ip4_ula3_netmask"
    mlc_net13_ip4_brc="$mlc_ip4_ula3_broadcast"
    mlc_net13_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula3_prefix $mlc_net1_mac 1)"
    mlc_net13_ula_mask="48"
    mlc_net13_rip_addr="$mlc_ip6_ripe3_prefix:$mlc_node::13"
    mlc_net13_rip_mask="128"


    idx="2"
    mlc_net2_link="${mlc_bridge_prefix}${idx}"
    mlc_net2_name="${mlc_dev_prefix}${idx}"
    mlc_net2_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net2_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net21_name="${mlc_dev_prefix}${idx}.11"
    mlc_net21_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net21_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net21_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net21_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net2_mac 1)"
    mlc_net21_ula_mask="48"
    mlc_net21_rip_addr="$mlc_ip6_ripe1_prefix:$mlc_node::21"
    mlc_net21_rip_mask="128"

    mlc_net22_name="${mlc_dev_prefix}${idx}.12"
    mlc_net22_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net22_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net22_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net22_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net2_mac 1)"
    mlc_net22_ula_mask="48"
    mlc_net22_rip_addr="$mlc_ip6_ripe2_prefix:$mlc_node::22"
    mlc_net22_rip_mask="128"

    mlc_net23_name="${mlc_dev_prefix}${idx}.13"
    mlc_net23_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula3_prefix1 $mlc_node $idx )" 
    mlc_net23_ip4_mask="$mlc_ip4_ula3_netmask"
    mlc_net23_ip4_brc="$mlc_ip4_ula3_broadcast"
    mlc_net23_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula3_prefix $mlc_net2_mac 1)"
    mlc_net23_ula_mask="48"
    mlc_net23_rip_addr="$mlc_ip6_ripe3_prefix:$mlc_node::23"
    mlc_net23_rip_mask="128"


# NS3 Links:
    idx="3"
    mlc_net3_name="${mlc_dev_prefix}${idx}"
    mlc_net3_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net3_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net3_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net3_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net3_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net3_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net3_mac 1)"
    mlc_net3_ula_mask="96"

#    mlc_net31_name="eth${idx}.11"
#    mlc_net31_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
#    mlc_net31_ip4_mask="$mlc_ip4_ula1_netmask"
#    mlc_net31_ip4_brc="$mlc_ip4_ula1_broadcast"
#    mlc_net31_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net3_mac 1)"
#    mlc_net31_ula_mask="96"
#
#    mlc_net32_name="eth${idx}.12"
#    mlc_net32_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
#    mlc_net32_ip4_mask="$mlc_ip4_ula2_netmask"
#    mlc_net32_ip4_brc="$mlc_ip4_ula2_broadcast"
#    mlc_net32_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net3_mac 1)"
#    mlc_net32_ula_mask="96"

# Peer2Peer Links:
    idx="4"
    mlc_net4_name="${mlc_dev_prefix}${idx}"
    mlc_net4_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net4_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net41_name="eth${idx}.11"
    mlc_net41_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net41_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net41_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net41_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net4_mac 1)"
    mlc_net41_ula_mask="96"

    mlc_net42_name="eth${idx}.12"
    mlc_net42_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net42_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net42_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net42_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net4_mac 1)"
    mlc_net42_ula_mask="96"

    idx="5"
    mlc_net5_name="${mlc_dev_prefix}${idx}"
    mlc_net5_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net5_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net51_name="eth${idx}.11"
    mlc_net51_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net51_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net51_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net51_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net5_mac 1)"
    mlc_net51_ula_mask="96"

    mlc_net52_name="eth${idx}.12"
    mlc_net52_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net52_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net52_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net52_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net5_mac 1)"
    mlc_net52_ula_mask="96"

    idx="6"
    mlc_net6_name="${mlc_dev_prefix}${idx}"
    mlc_net6_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net6_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net61_name="eth${idx}.11"
    mlc_net61_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net61_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net61_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net61_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net6_mac 1)"
    mlc_net61_ula_mask="96"

    mlc_net62_name="eth${idx}.12"
    mlc_net62_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net62_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net62_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net62_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net6_mac 1)"
    mlc_net62_ula_mask="96"

    idx="7"
    mlc_net7_name="${mlc_dev_prefix}${idx}"
    mlc_net7_mac="$(MLC_calc_mac $mlc_node $idx )"
    mlc_net7_veth="$(MLC_calc_veth_name $mlc_node $idx )"

    mlc_net71_name="eth${idx}.11"
    mlc_net71_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula1_prefix1 $mlc_node $idx )" 
    mlc_net71_ip4_mask="$mlc_ip4_ula1_netmask"
    mlc_net71_ip4_brc="$mlc_ip4_ula1_broadcast"
    mlc_net71_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula1_prefix $mlc_net7_mac 1)"
    mlc_net71_ula_mask="96"

    mlc_net72_name="eth${idx}.12"
    mlc_net72_ip4_addr="$(MLC_calc_ip4 $mlc_ip4_ula2_prefix1 $mlc_node $idx )" 
    mlc_net72_ip4_mask="$mlc_ip4_ula2_netmask"
    mlc_net72_ip4_brc="$mlc_ip4_ula2_broadcast"
    mlc_net72_ula_addr="$(MLC_ip6_ula $mlc_ip6_ula2_prefix $mlc_net7_mac 1)"
    mlc_net72_ula_mask="96"
}


MLC_assign_networks $mlc_node

mlc_deb_packages="\
aptitude \
ca-certificates \
ifupdown \
netbase \
net-tools \
iproute vlan bridge-utils \
iptables \
openssh-server \
iputils-ping \
vim nano less \
locales-all \
dialog \
netdiag \
man-db \
ipcalc ipv6calc \
wget \
bzip2 \
unzip \
build-essential gdb file subversion git-core \
lynx \
telnet \
tcpdump \
wireshark-common \
mtr traceroute \
psmisc lsof \
iptraf  netcat iperf  \
bison flex m4 autoconf autoconf-archive cmake autogen dh-autoreconf gawk \
libjson-c-dev zlib1g-dev libiw-dev \
mini-httpd \
nmap \

"

mlc_deb_packages_disabled="\
quagga quagga-doc \
texinfo \
"

mlc_sources="\
mbedtls-2.4.0::https://tls.mbed.org/download/mbedtls-2.4.0-gpl.tgz \
olsrd-0.9.6::http://www.olsr.org/releases/0.9/olsrd-0.9.6.tar.gz \
babeld-1.8.0::http://www.pps.jussieu.fr/~jch/software/files/babeld-1.8.0.tar.gz \
"

mlc_gits=" \
uci.git::https://github.com/axn/uci-0.7.5.git \
bmx7.git::https://github.com/bmx-routing/bmx7.git \
oonf.git::https://github.com/OLSR/OONF.git \
"



mlc_help() {

    local mother_name="${mlc_name_prefix}${mlc_mother_id}"

    less mlc-help.txt
}

mlc_rand() {
    local max=${1:-"1000"}
    local min=${2:-"0"}
    echo $((( ( $(dd if=/dev/random bs=4 count=1 2>/dev/null | hexdump -e '"%u\n"') % (($max + 1) - $min) ) + $min )))
}



mlc_gprof() {

	local nodeMax="${1:-$mlc_min_node}"
	local nodeMin="${2:-$mlc_min_node}"
	# local nodeMin="${2:-$nodeMax}"
	local binary="bmx6"
	local binary_path="usr/sbin"
	local gmon_dir="gprofs"
	local gmon_out="root/gmon.out"
	local now="$(date +%y%m%d%H%M%S)"
	local gmon_bin="./$gmon_dir/gmon.$now.bin"
	local gmon_SUM="./$gmon_dir/gmon.$now.sum"
	local gmon_sum="./gmon.sum"
	local gmon_txt="./$gmon_dir/gmon.$now.txt"
	local mother_name="${mlc_name_prefix}${mlc_mother_id}"
	local mother_rootfs=$mlc_conf_dir/$mother_name/rootfs
	local vm_min_rootfs=$mlc_conf_dir/$mlc_name_prefix$nodeMin/rootfs

	mkdir -p $gmon_dir

	cp $mother_rootfs/$binary_path/$binary $gmon_bin
	cp $mother_rootfs/$binary_path/$binary $gmon_bin.strip
	strip                                  $gmon_bin.strip

	echo "cp       $vm_min_rootfs/$gmon_out  $gmon_sum"
	      cp       $vm_min_rootfs/$gmon_out  $gmon_sum
	ls --full-time $vm_min_rootfs/$gmon_out  $gmon_sum


	local node
	for node in $( seq $(( $nodeMin + 1 )) $nodeMax ) ; do 

	    local vm_rootfs=$mlc_conf_dir/$mlc_name_prefix$node/rootfs

	    echo "gprof -s $gmon_bin  $vm_rootfs/$gmon_out  $gmon_sum"
                  gprof -s $gmon_bin  $vm_rootfs/$gmon_out  $gmon_sum
	    ls --full-time            $vm_rootfs/$gmon_out  $gmon_sum

	done

	cp $gmon_sum $gmon_SUM
	gprof $gmon_bin $gmon_SUM > $gmon_txt

	less $gmon_txt

}



mlc_cpu_set(){
	local GOVERNOR=$1
	if [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors ]; then
	 for i in `seq 0 $(($(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_available_governors | wc -l) -1))`; do
	  if grep -q $GOVERNOR /sys/devices/system/cpu/cpu$i/cpufreq/scaling_available_governors ; then
	   if cpufreq-set -c $i -g $GOVERNOR ; then
	    echo "Success setting cpu$i $GOVERNOR governor"
	   else
	    echo "WARNING: Could not set cpu$i $GOVERNOR governor"
	   fi
	  fi
	 done
	else
	 echo "WARNING: unable to set cpus' $GOVERNOR governor"
	fi
	cpufreq-info
}


mlc_cpu_max() {
	mlc_cpu_set performance
}

mlc_cpu_min() {
	mlc_cpu_set powersave
}



mlc_cpu_sleep_until_idle() {

  local min=$mlc_cpu_idle_assumption
  local cpus=$(cat /proc/cpuinfo | grep processor | wc -l )
  local probeA=$(grep 'cpu ' /proc/stat | awk '{print $5}')

  while true; do
      local probeB=$(sleep 0.4; grep 'cpu ' /proc/stat | awk '{print $5}')
      local idle=$((( -100 * ( $probeA - $probeB) / (40 * $cpus) )))

      echo "cpus=$cpus idle=$idle min=$min , $( [ "$idle" -lt "$min" ] && echo "WAITING...")"

      [ "$idle" -lt "$min" ] || break
      
      probeA=$probeB
  done

}

MLC_loop_boot() {
#  set -x
  local node=$1
  local name="$mlc_name_prefix$1"

  lxc-info --name $name | grep -q RUNNING && echo "$name already RUNNING" || lxc-start -n $name -d
}



MLC_loop_help() {
  echo available long options are: $longopts
  echo available short options are: $shortopts
}

mlc_loop() {
  # set -x

  local loop_min=$mlc_min_node
  local loop_max=$mlc_max_node

  local loop_help=0
  local loop_create=0
  local loop_boot=0
  local loop_load=0 
  local loop_stop=0
  local loop_destroy=0
  local loop_pretend=""
  local loop_update=0

  local loop_exec="0"

  local shortopts="hpcubsdli:a:e:C:"
  local longopts="help,pretend,create,update;boot,stop,destroy,load,min:,max:,hosts,exec:,config:"


  local TEMP=$(getopt -o $shortopts --long $longopts -- "$@")
  if [ $? != 0 ] ; then echo "Terminating..." >&2 ; return 1 ; fi

  # Note the quotes around `$TEMP': they are essential!
  eval set -- "$TEMP"

  while true ; do
	  # echo evaluating $@
	  case "$1" in
		  -h|--help)	 MLC_loop_help; return 0;;
		  -i|--min)	 loop_max=$2 loop_min=$2 ; shift 2 ;;
		  -a|--max)	 loop_max=$2 ; shift 2 ;;
		  -c|--create)	 loop_create=1 ; shift 1 ;;
		  -u|--update)	 loop_update=1 ; shift 1 ;;
		  -b|--boot)	 loop_boot=1 ; shift 1 ;;
		  -s|--stop)	 loop_stop=1 ; shift 1 ;;
		  -l|--load)	 loop_load=1 ; shift 1 ;;
		  -d|--desroy)	 loop_destroy=1 ; shift 1 ;;
		  -p|--pretend)	 loop_pretend="echo"; shift 1;;
		  -e|--exec)	 loop_exec=$2; shift 2;;
		  --) shift ; break ;;
		  *) echo "Internal error!" ; return 1 ;;
	  esac
  done

  for node in $( seq $loop_min $loop_max ) ; do
      local loop_name="$mlc_name_prefix$node"

      [ "$loop_load" == "1" ]    &&  mlc_cpu_sleep_until_idle
      [ "$loop_create" == "1" ]  && echo "creating   $loop_name" && $loop_pretend mlc_create_child $node && sync
      [ "$loop_update" == "1" ]  && echo "updating   $loop_name" && $loop_pretend mlc_update_individual $node
      [ "$loop_boot" == "1" ]    && echo "booting    $loop_name" && \
	  mlc_cpu_sleep_until_idle  &&  sync  && $loop_pretend MLC_loop_boot $node
      [ "$loop_stop" == "1" ]    && echo "stopping   $loop_name" && $loop_pretend lxc-stop -kn $mlc_name_prefix$node #-t 1
      [ "$loop_destroy" == "1" ] && echo "destroying $loop_name" && $loop_pretend mlc_destroy $node
#     [ "$loop_exec" != "0" ]    && echo "executing  $loop_name $loop_exec" && $loop_pretend $mlc_ssh root@"$(MLC_calc_ip4 $mlc_ip4_admin_prefix1 $node $mlc_admin_idx )" $loop_exec
      [ "$loop_exec" != "0" ]    && echo "executing  $loop_name $loop_exec" && $loop_pretend lxc-attach -n $loop_name -- $loop_exec
  done

  [ "$loop_boot" == "1" ]    &&  $loop_pretend  mlc_veth_obtain

}


MLC_transform_long_mac() {

  local long=$1

  printf "%X:%X:%X:%X:%X:%X\n" \
         $(( 16#$(echo $long | awk -F: '{print $1}') )) \
         $(( 16#$(echo $long | awk -F: '{print $2}') )) \
         $(( 16#$(echo $long | awk -F: '{print $3}') )) \
         $(( 16#$(echo $long | awk -F: '{print $4}') )) \
         $(( 16#$(echo $long | awk -F: '{print $5}') )) \
         $(( 16#$(echo $long | awk -F: '{print $6}') ))

}


MLC_setup_bridge() {
  local link=$1
  local addr=$2
  local mask=$3
  local brc=$4

  if [ -z "$link" ] ; then
    echo something is not defined
    return 0
  fi

  if brctl show | grep "^$link$" ; then
      echo link $link already setup
  else
      echo setup $link
      brctl addbr $link
  fi

  if [ -z "$addr" ] ; then
     echo no address given
  else
     ip addr add $addr/$mask br $brc dev $link 
#      ifconfig $link $addr  netmask $mask  broadcast $brc
      ip link set $link address 0:$(printf "%X" $(echo $addr | awk -F. '{print $4}')):$(printf "%X" $(echo $addr | awk -F. '{print $3}')):0:0:0
  fi

      brctl setfd $link 0
      ifconfig $link up
      ifconfig $link promisc

 echo 1 > /sys/devices/virtual/net/$link/bridge/multicast_snooping
}


mlc_peer_prepare() {

    for idx in $( seq $mlc_peer_idx_min $mlc_peer_idx_max ) ; do
	ebtables -I FORWARD -s $mlc_mac_prefix:0:0:$idx/FF:FF:FF:0:0:FF -j ACCEPT
    done

}


mlc_peer_clear() {

    local nodeA=$1
    local nodeB=${2:-$nodeA}

    local bridge=""

    if [ -z $nodeA ] ; then
	echo "usage: mlc_peer_clear <nodeA> [nodeB]"; return 1;
    fi
    
    if ! ip link show | grep ${mlc_p2p_bridge_delimiter} | grep ${mlc_p2p_bridge_prefix}${nodeA} | grep ${mlc_p2p_bridge_prefix}${nodeB} > /dev/null 2>&1 ; then
	return 1;
    fi


    local bridges="$( ip link show | grep ${mlc_p2p_bridge_delimiter} | grep ${mlc_p2p_bridge_prefix}${nodeA} | grep ${mlc_p2p_bridge_prefix}${nodeB}  | awk -F': ' '{print $2}' )"
    local bridge=""

    echo "del bridge $bridges"

    for bridge in $bridges; do

#	local br
#	for br in $( echo $bridge | awk -F"$mlc_p2p_bridge_delimiter" '{print $1 " " $2}' ) ; do
#
#	    local bridge=$( echo $br | awk -F"$mlc_p2p_bridge_prefix" '{print $2}' )
#	    local nodeidx=$( echo $bridge | awk -F"$mlc_p2p_bridge_delimiter" '{print $1}' | awk -F"$mlc_p2p_bridge_prefix" '{print $2}' )
#	    local node=$( echo $nodeidx | awk -F"$mlc_p2p_bridge_idx_delimiter" '{print $1}' )
#	    local idx=$(  echo $nodeidx | awk -F"$mlc_p2p_bridge_idx_delimiter" '{print $2}' )
#
#	    ebtables -D FORWARD -o $(MLC_get_veth_cache $node $idx ) -j ACCEPT
#	done

    	ifconfig $bridge down
	brctl delbr $bridge
    done
}


MLC_peer_alloc_idx() {

    local node=$1
    local cache_file="$mlc_tmp_dir/MLC_peer_alloc_idx.tmp"

    ip link show | grep "${mlc_p2p_bridge_delimiter}" | grep "${mlc_p2p_bridge_prefix}${node}${mlc_p2p_bridge_idx_delimiter}" > $cache_file

    for idx in $( seq $mlc_peer_idx_min $mlc_peer_idx_max ) ; do
	
	if ! grep "${mlc_p2p_bridge_prefix}${node}${mlc_p2p_bridge_idx_delimiter}${idx}"  $cache_file > /dev/null 2>&1 ; then
	    echo "$idx"
	    return 0;
	fi

    done

    return 1;
}

mlc_peer_get() {

    local node=$1

    local links=$( ip link show | grep ${mlc_p2p_bridge_delimiter} | grep ${mlc_p2p_bridge_prefix}${node} | awk -F': ' '{print $2}' )
    local link

    for link in $links; do
	printf "%s " $link
    done

}

mlc_peer_set() {

    local node_a=$1
    local node_b=$2

    if [ -z $node_a ] || [ -z $node_b ] ; then
	echo "usage: mlc_peer_set <nodeA> <nodeB> [idxA] [idxB]"; return 1;
    fi

    if [ "$node_a" == "$node_b" ] ; then
	return 0
    fi

    if [ "$node_a" -gt "$node_b" ] ; then
	local node_x=$node_a
	node_a=$node_b
	node_b=$node_x
    fi
    
    mlc_peer_clear $node_a $node_b

    local idx_a=${3:-"$(MLC_peer_alloc_idx $node_a )"}
    local idx_b=${4:-"$(MLC_peer_alloc_idx $node_b )"}

    if [ -z $idx_a ] || [ -z $idx_b ] ; then
	echo "ERROR: no idx available"; return 1;
    fi
    

    local veth_a="$(MLC_get_veth_cache $node_a $idx_a)"
    local veth_b="$(MLC_get_veth_cache $node_b $idx_b)"

    if ! ip link show dev $veth_a > /dev/null 2>&1 || ! ip link show dev $veth_b > /dev/null ; then
	echo "veth interfaces could not be found"; return 1;
    fi

    local bridge_name="${mlc_p2p_bridge_prefix}${node_a}${mlc_p2p_bridge_idx_delimiter}${idx_a}${mlc_p2p_bridge_delimiter}${mlc_p2p_bridge_prefix}${node_b}${mlc_p2p_bridge_idx_delimiter}${idx_b}"

    echo "creating bridge $bridge_name ifA $veth_a ifB $veth_b"

    brctl addbr $bridge_name
    brctl setfd $bridge_name 0
    ifconfig    $bridge_name up
    ifconfig    $bridge_name promisc


    brctl addif $bridge_name $veth_a
    brctl addif $bridge_name $veth_b

#    ebtables -I FORWARD -o $veth_a -j ACCEPT
#    ebtables -I FORWARD -o $veth_b -j ACCEPT
}


MLC_get_veth_cache() {

  local node=$1
  local idx=$2
  local name="${mlc_name_prefix}${node}"

  if lxc-info -n $name | grep -q RUNNING ; then
      echo "$( MLC_calc_veth_name $node $idx )"; return 0;
  fi

  echo "Failed to resolve if name for $name $idx"; return 1;

}


mlc_ls() {
  for name in $(lxc-ls | sort -u); do
    if lxc-info -n $name | grep -q RUNNING ; then
      printf "%-10s %-10s %s \n" $name "RUNNING " "$( mlc_peer_get $(echo $name | awk -F $mlc_name_prefix '{print $2}' ) )"

    fi
  done
}


MLC_veth_obtain() {
#set -x
  local name=
  local dev=
  local cache_file="$mlc_tmp_dir/MLC_veth_obtain.tmp"

  printf "%-10s %-10s\n" "container:"  "state:"

  for name in $(lxc-ls  | grep $mlc_name_prefix | sort -u); do
    if echo "$name" | grep -q "$mlc_name_prefix" && lxc-info -n $name| grep -q RUNNING ; then
      printf "%-10s %-10s " $name "RUNNING"

      local node=$( echo $name | awk -F"$mlc_name_prefix" '{print $2}'  )
      local node_ip="$(MLC_calc_ip4 $mlc_ip4_admin_prefix1 $node $mlc_admin_idx )"

      if ping -n -c1 $node_ip > /dev/null ; then
	  
#	      for dev in $( $mlc_ssh root@$node_ip ip link | tee $cache_file | grep ": ${mlc_dev_prefix}" | grep -v "@" | awk -F ': ' '{print $2}' | sort -u) ; do
	      for dev in $( lxc-attach -n $name -- ip link | tee $cache_file | grep ": ${mlc_dev_prefix}" | grep -v "@" | awk -F ': ' '{print $2}' | sort -u) ; do

		printf "%8s: " $dev


		local iif_lxc_line=$( cat $cache_file | grep " $dev:" )
		if [ $? -ne 0 ]; then
		    echo "Failed to resolve lxc iif for $name $d"; return 1
		fi

		local iif_lxc=$(echo $iif_lxc_line | awk -F ':' '{print $1}')

		let iif_host=$(( $iif_lxc + 1 ))
		if [ $? -ne 0 ]; then
		    echo "Failed to calculate host ifi for $name $dev $iif_lxc"; return 1
		fi
    
		local host_dev=$(ip link show | grep -e "^$iif_host: $mlc_veth_prefix" )
		if [ $? -ne 0 ]; then
		    echo "Failed to resolve if name for $name $dev $iif_lxc $iif_host"; return 1
		fi

    
		local veth=$( echo $host_dev | awk -F ': ' '{print $2}' )


		if [ "$veth" == "" ]; then
		  printf "ERROR: interface error\n"
		  echo "host_dev=$host_dev iif_host=$iif_host mlc_veth_prefix=$mlc_veth_prefix"
		else
		  printf "%-10s  " $veth
		fi

	      done
      else
	printf "ERROR: not reachable"
      fi

    else
      printf "%-6s %-10s " "$name" "???"
    fi
    printf "\n"
  done

}

mlc_veth_obtain() {
  
  MLC_veth_obtain | tee $mlc_veth_cache

}

mlc_veth_show() {
  
  cat $mlc_veth_cache

}


mlc_veth_force_cleanup() {

  for dev in $(ip link show | grep $mlc_veth_prefix | awk -F ': ' '{print $2}') ; do
    if ip link show | grep ": $dev:" ; then
      echo "ip link delete dev $dev"
      ip link delete dev $dev
    else
      echo "ip link dev $dev already removed"
    fi
  done
}


mlc_net_flush() {
  ebtables -P FORWARD DROP
  ebtables --flush FORWARD
#  ebtables -I FORWARD --logical-out mlc0 -j DROP
#  ebtables -I FORWARD --logical-out mlc1 -j DROP
#  ebtables -I FORWARD --logical-out mlc2 -j DROP

}


mlc_qdisc_clear() {
    local idx_list=${1:-"1 2"}
    local idx

#   mlc_net_flush
    
    for idx in $idx_list ; do

	echo "clearing qdisc idx=$idx of idx_list=$idx_list"
	local dev
	
	for dev in $( tc qdisc | grep "qdisc prio 1: dev $mlc_veth_prefix" | grep "_$idx" |  awk -F 'dev ' '{print $2}' | awk '{print $1 }' ) ; do
	    echo "setting qdisc rules for dev $dev"
  	    tc qdisc del dev $dev root
	done

    done
}

MLC_qdisc_set_rule() {

  local dev=$1
  local mark=$2
  local delay=$3
  local delay_correlation=$4
  local loss=$5
  local loss_correlation=$6
  tc qdisc  add dev $dev parent 1:$(printf "0x%X" $mark) netem loss $loss $loss_correlation delay $delay
  tc filter add dev $dev parent 1:0 protocol all  prio 1   handle $(printf "0x%X" $mark) fw flowid 1:$(printf "0x%X" $mark)
# tc filter add dev $dev parent 1:0 protocol ip   prio 2   handle $(printf "0x%X" $mark) fw flowid 1:$(printf "0x%X" $mark)
# tc filter add dev $dev parent 1:0 protocol ipv6 prio 3   handle $(printf "0x%X" $mark) fw flowid 1:$(printf "0x%X" $mark)
}

MLC_qdisc_set_rules() {
  local dev=$1

    if tc qdisc | grep -q "qdisc prio 1: dev $dev" ; then
      tc qdisc del dev $dev root
    fi
  
  tc qdisc add dev $dev root handle 1: prio bands 16 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
#  tc qdisc add dev $a_veth parent 1:1  netem loss 100%
  
#                           delay corr loss correlation 
  MLC_qdisc_set_rule $dev 3  0.1ms  0%   0%  0% #BroadCast
  MLC_qdisc_set_rule $dev 4  0.1ms  0%   0%  0% #UniCast

  MLC_qdisc_set_rule $dev 5  0.2ms  0%   10%  0% #BroadCast
  MLC_qdisc_set_rule $dev 6  0.4ms  0%   0%  0% # 0.2% #UniCast
#  MLC_qdisc_set_rule $dev 5  0.2ms  0%   0%  0% #BroadCast
#  MLC_qdisc_set_rule $dev 6  0.4ms  0%   2%  0% # 0.2% #UniCast

  MLC_qdisc_set_rule $dev 7  0.3ms  0%   20%  0% #BroadCast
  MLC_qdisc_set_rule $dev 8  1.6ms  0%   0%  0% #0.5% #UniCast
#  MLC_qdisc_set_rule $dev 7  0.3ms  0%   0%  0% #BroadCast
#  MLC_qdisc_set_rule $dev 8  1.6ms  0%   5%  0% #0.5% #UniCast

  MLC_qdisc_set_rule $dev 9  0.4ms  0%   30% 0% #BroadCast
  MLC_qdisc_set_rule $dev 10 6.4ms  0%   0%  0% #1% #UniCast
#  MLC_qdisc_set_rule $dev 9  0.4ms  0%   0% 0% #BroadCast
#  MLC_qdisc_set_rule $dev 10 6.4ms  0%   10%  0% #1% #UniCast

  MLC_qdisc_set_rule $dev 11 0.5ms  0%   40% 0% #BroadCast
  MLC_qdisc_set_rule $dev 12 25ms   0%   0%  0% #2% #UniCast
#  MLC_qdisc_set_rule $dev 11 0.5ms  0%   0% 0% #BroadCast
#  MLC_qdisc_set_rule $dev 12 25ms   0%   20%  0% #2% #UniCast

  MLC_qdisc_set_rule $dev 13 0.6ms  0%   50% 0% #0.8ms 25% BroadCast
  MLC_qdisc_set_rule $dev 14 100ms  0%   0%  0% #5% #UniCast
#  MLC_qdisc_set_rule $dev 13 0.6ms  0%   0% 0% #0.8ms 25% BroadCast
#  MLC_qdisc_set_rule $dev 14 100ms  0%   40%  0% #5% #UniCast

  MLC_qdisc_set_rule $dev 15 0.7ms  0%   60% 0% #1ms 40% BroadCast
  MLC_qdisc_set_rule $dev 16 400ms  0%   0%  0% #10% #UniCast
#  MLC_qdisc_set_rule $dev 15 0.7ms  0%   0% 0% #1ms 40% BroadCast
#  MLC_qdisc_set_rule $dev 16 400ms  0%   80%  0% #10% #UniCast

}

mlc_qdisc_prepare() {
  local idx_list=${1:-"0 1 2 3 6"}
  local idx
  for idx in $idx_list ; do
    echo "setting qdisc idx=$idx of idx_list=$idx_list"
    local dev
    for dev in $( cat $mlc_veth_cache | grep "RUNNING" | awk -F"${mlc_dev_prefix}${idx}:" '{print $2}' | awk '{print $1 }' ) ; do
      echo "setting qdisc rules for idx=$idx $dev"
      MLC_qdisc_set_rules $dev
    done
  done
}

MLC_link_get() {

  local src=$1
  local oif=$2
  local mark_mc mark_uc mark_bc


#  mark_mc="$(ebtables -L FORWARD | grep -ie "-s $src -d $mlc_mac6_multicast -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}')"
  mark_bc="$(ebtables -L FORWARD | grep -ie "-s $src -d Broadcast -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}')"
  mark_uc="$(ebtables -L FORWARD | grep -ie "-s $src -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}')"

  echo "obtaining old lq for src $src oif $oif mark $mark_mc $mark_bc $mark_uc" >&2

  if [ -z $mark_mc ] && [ -z $mark_bc ] && [ -z $mark_uc ]; then
    echo 0;
    return 0;
  fi


  if [ "$(( $mark_bc + 1 ))" != "$(( $mark_uc ))" ] ; then
    echo "Failed to obtain old lq for src $src oif $oif mark $mark_bc $mark_uc" >&2
    return 1;
  fi
  
  echo "$(( $mark_bc ))"
  
}


mlc_link_clear() {

  local src_long="$1"
  local src="$(MLC_transform_long_mac $src_long)"
  local oif="$2"

  echo "mlc_link: src=$src_long -> oif=$oif "

  for mark in $(ebtables -L FORWARD | grep -ie "-s $src -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}') ; do
    ebtables -D FORWARD -s $src -o $oif -j mark --mark-set $mark --mark-target ACCEPT
  done

  for mark in $(ebtables -L FORWARD | grep -ie "-s $src -d Broadcast -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}') ; do
    ebtables -D FORWARD -s $src -d Broadcast -o $oif -j mark --mark-set $mark --mark-target ACCEPT
  done

  for mark in $(ebtables -L FORWARD | grep -ie "-s $src -d $mlc_mac6_multicast -o $oif -j mark --mark-set " | awk -F 'mark-set ' '{print $2}' | awk '{print $1}') ; do
    ebtables -D FORWARD -s $src -d $mlc_mac6_multicast -o $oif -j mark --mark-set $mark --mark-target ACCEPT
  done

}

mlc_link_set() {
  
  local cmd="mlc_link_set"

  if [ -z $1 ] || [ -z $2 ] || [ -z $3 ] || [ -z $4 ] || [ -z $5 ]; then 
    printf "usage:   $cmd ifnA nodeA ifnB nodeB txA  txB  purgeFlag \n" 
    printf "example: $cmd    1 $mlc_min_node  1    $(( $mlc_min_node + 1 ))  3    [13] [1] \n" 
    return 1
  fi

  local a_ifn=$1
  local a_node=$2
  local b_ifn=$3
  local b_node=$4
  local a_tq=$5
  local b_tq=${6:-$a_tq}
  local purge=${7:-1}

  
  local a_mark_bc=$a_tq #0x2 #2,4,6,..14
  local a_mark_uc=$(( $a_mark_bc + 1 ))
  local b_mark_bc=$b_tq #0x2 #2,4,6,..14
  local b_mark_uc=$(( $b_mark_bc + 1 ))
  
  local a_mac="$( MLC_calc_mac $a_node $a_ifn )"
  local b_mac="$( MLC_calc_mac $b_node $b_ifn )"
  local a_veth
  local b_veth
  
  a_veth="$( MLC_get_veth_cache $a_node $a_ifn )"
    if [ $? -ne 0 ]; then
	echo "Failed to resolve veth for $a_veth"
	return 1
    fi

  b_veth="$( MLC_get_veth_cache $b_node $b_ifn )"
    if [ $? -ne 0 ]; then
	echo "Failed to resolve veth for $b_veth"
	return 1
    fi

  echo mlc_link_set ${mlc_dev_prefix}$a_ifn $a_node $a_veth TQ=$a_tq -- ${mlc_dev_prefix}$b_ifn $b_node $b_veth TQ=$b_tq

  [ "$a_tq" != "0" ] || [ "$purge" != "0" ] && mlc_link_clear $a_mac $b_veth

  if [ "$a_tq" != "0" ] ; then
      ebtables -A FORWARD -s $a_mac -d $mlc_mac6_multicast -o $b_veth  -j mark --set-mark $(printf "0x%X" $a_mark_bc) --mark-target ACCEPT
      ebtables -A FORWARD -s $a_mac -d Broadcast           -o $b_veth  -j mark --set-mark $(printf "0x%X" $a_mark_bc) --mark-target ACCEPT
      ebtables -A FORWARD -s $a_mac                        -o $b_veth  -j mark --set-mark $(printf "0x%X" $a_mark_uc) --mark-target ACCEPT
  fi

  [ "$b_tq" != "0" ] || [ "$purge" != "0" ] && mlc_link_clear $b_mac $a_veth

  if [ "$b_tq" != "0" ] ; then
      ebtables -A FORWARD -s $b_mac -d $mlc_mac6_multicast -o $a_veth  -j mark --set-mark $(printf "0x%X" $b_mark_bc) --mark-target ACCEPT
      ebtables -A FORWARD -s $b_mac -d Broadcast           -o $a_veth  -j mark --set-mark $(printf "0x%X" $b_mark_bc) --mark-target ACCEPT
      ebtables -A FORWARD -s $b_mac                        -o $a_veth  -j mark --set-mark $(printf "0x%X" $b_mark_uc) --mark-target ACCEPT
  fi

}

mlc_mac_set() {

  [ -z $1 ] && \
echo "example: mlc_mac_set <dev_idx> <nodeA>  <phyDev> <macOfPeerDev>   <lq>" && \
echo "example: mlc_mac_set    1       1001     ${mlc_dev_prefix}0   p00:00:00:00:00:AA  3 "  && \
return 1

  local ifn=$1
  local a=$2
  local dev=$3
  local dev_mac=$4
  local lq=$5
  
  local mark_bc=$lq #0x2 #2,4,6,..14
  local mark_uc=$(( $mark_bc + 1 ))
  
  local a_mac="$( MLC_calc_mac $a $ifn )"

  local a_veth
  
  a_veth="$( MLC_get_veth_cache $a $ifn )"
    if [ $? -ne 0 ]; then
	echo "Failed to resolve veth for $a_veth"
	return 1
    fi

  echo mlc_mac_set $a $a_veth $a_mac -- $dev_mac $dev dev=${mlc_dev_prefix}$ifn  LQ=$lq

  mlc_link_clear $dev_mac $a_veth

  [ "$lq" != "0" ] && ebtables -A FORWARD -s $dev_mac -d $mlc_mac6_multicast -o $a_veth -j mark --set-mark $(printf "0x%X" $mark_bc) --mark-target ACCEPT
  [ "$lq" != "0" ] && ebtables -A FORWARD -s $dev_mac -d Broadcast           -o $a_veth -j mark --set-mark $(printf "0x%X" $mark_bc) --mark-target ACCEPT
  [ "$lq" != "0" ] && ebtables -A FORWARD -s $dev_mac                        -o $a_veth -j mark --set-mark $(printf "0x%X" $mark_uc) --mark-target ACCEPT

  mlc_link_clear $a_mac $dev

  [ "$lq" != "0" ] && ebtables -A FORWARD -s $a_mac   -d $mlc_mac6_multicast -o $dev    -j mark --set-mark $(printf "0x%X" $mark_bc) --mark-target ACCEPT
  [ "$lq" != "0" ] && ebtables -A FORWARD -s $a_mac   -d Broadcast           -o $dev    -j mark --set-mark $(printf "0x%X" $mark_bc) --mark-target ACCEPT
  [ "$lq" != "0" ] && ebtables -A FORWARD -s $a_mac                          -o $dev    -j mark --set-mark $(printf "0x%X" $mark_uc) --mark-target ACCEPT

  ifconfig $dev up

  local br;  for br in $( brctl show | grep mlc | awk '{print $1}'); do brctl delif $br $dev ; echo "in bridge $br"; done

  brctl show  $mlc_bridge_prefix$ifn | grep "$dev$" || \
      brctl addif $mlc_bridge_prefix$ifn $dev

  MLC_qdisc_set_rules $dev
  MLC_qdisc_set_rules $a_veth
}

mlc_link_periodicy() {
  local cmd="mlc_link_periodicy"
  local lq_default="15 13 11 9 7 5 3 3 5 7 9 11 13 15 "

  if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]; then 
    printf "usage:   $cmd ifn nodea nodeb pause [s]  duration [s] \"lq1 lq2 ...\"\n" 
    printf "example: $cmd 1   100   109   1          100          \"$lq_default\" \n" 
    return 1
  fi
  
  local ifn=$1
  local a=$2
  local b=$3
  local period="${4:-1}"
  local duration="${5:-14}"
  local lqs="${6:-$lq_default}"

  local a_mac="$( MLC_calc_mac $a $ifn )"

  local b_veth
  local lq_old
  
  b_veth="$( MLC_get_veth_cache $b $ifn )"
    if [ $? -ne 0 ]; then
	echo "Failed to resolve veth for mlc$b"
	return 1
    fi

  lq_old="$( MLC_link_get $a_mac $b_veth )"
    if [ $? -ne 0 ]; then
	echo "Failed to resolve link-qualtiy for link $ifn $a -- $b $a_mac $b_veth"
	return 1
    fi

  printf "varying link-quality of channel $ifn  link $a -- $b  range [$lqa..$lqb] $lq_old   period $period s  for $duration s \n"
  
  local start="$(date +%s)"
  local stop=$(( start + duration ))
  
  echo $start $stop
  
  while [ $stop -ge $(date +%s) ]; do
    for lq in $lqs; do
    mlc_link_set  $ifn $a  $ifn $b  $lq
    sleep $(( $period ))
    done
  done
  
  mlc_link_set  $ifn $a  $ifn $b $(( $lq_old ))
  
}



mlc_get_max_node() {
  local node="" 
  local max_node=""
  for node in $( mlc_veth_show | grep RUNNING | awk '{print $1}' | awk -F 'mlc' {'print $2}' ) ; do
    max_node=$node
  done
  [ -z $max_node ] && return 1
  echo $max_node
}


mlc_configure_line() {
  [ -z $1 ] &&\
     echo "mlc_configure_line <dev_index> [tq] [loop_tq] [max_node] [rq] [loop_rq] [min_node] [purgeFlag]" &&\
     echo "example: mlc_configure_line 1  [3]  [5]       [$mlc_max_node]     [13] [15]      [$mlc_min_node]     [1]" &&\
     return 1

#assign default values see:http://snipplr.com/view/11080/setting-default-value-for-bash-variable/
  local ifn=$1
  local tq=${2:-3}  # assign default value of 3 if $2 is not set
  local loop_tq=${3:-0}
  local max=${4:-$( mlc_get_max_node )}
  local rq=${5:-$tq}  # assign default value of 3 if $2 is not set
  local loop_rq=${6:-$loop_tq}
  
  local min=${7:-$mlc_min_node}
  local purge=${8:-$1}



  for node in $( seq $min $max ) ; do
    if [ $node -ne $max ] ; then
      mlc_link_set  $ifn $node   $ifn $(( $node + 1 ))  $tq      $rq      $purge
    else
      mlc_link_set  $ifn $node   $ifn $min              $loop_tq $loop_rq $purge
    fi
  done

}



mlc_configure_grid() {
  [ -z $1 ] &&\
     echo "mlc_configure_grid <dev_idx> [lq] [loop_x_lq] [loop_y_lq] [0=ortographic,1=diagonal] [distance] [max_node] [min_node] [rq] [loop_x_rq] [loop_y_rq] [columns] [purge]"  &&\
     echo "example: mlc_configure_grid 1 9 0 0 0 1 119 10 1 # configures a grid of 2x10 nodes with links to each 1 hop-neighbor of lq=3 and purge previous affected links" &&\
     echo "example: mlc_configure_grid 1                  # will do the same with all nodes and lq=3" &&\
     return 1

  local ifn=$1
  local default_lq=${2:-3}
  local loop_x_lq=${3:-0}
  local loop_y_lq=${4:-0}
  local diagonal=${5:-0}
  local distance=${6:-1}
  local max=$( mlc_get_max_node )
  local max=${7:-$max}
  local min=${8:-$mlc_min_node}
  local default_rq=${9:-$default_lq}
  local loop_x_rq=${10:-$loop_x_lq}
  local loop_y_rq=${11:-$loop_y_lq}
  local row_size=${12:-$10}
  local purge=${13:-1}

  local x_max=$(( $row_size - 1 ))
  local y_max=$(( ( ( ( $max - $min )  + 1 ) / $row_size ) - 1 )) 

  local col_size=$(( $y_max + 1 ))

  local x0 x1 y0 y1 x_wrap y_wrap x_curr y_curr curr x_next y_next right_lq down_lq right_rq down_rq

  echo "$0 ifn=$ifn lq=$default_lq/$default_rq x_lq=$loop_x_lq/$loop_x_rq y_lq=$loop_y_lq/$loop_y_rq diagonal=$diagonal distance=$distance min=$min max=$max x_max=$x_max y_max=$y_max row_size=$row_size"

  for y0 in $( seq 0 $y_max ) ; do
      let y1=$(( $y0 + $distance ))

      for x0 in $( seq 0 $x_max ) ; do
	let x1=$(( $x0 + $distance ))

        let x_wrap=$(( $x_max - $distance ))
        let y_wrap=$(( $y_max - $distance ))
        let x_curr=$x0
        let y_curr=$(( ( $row_size * $y0 ) ))
#       let curr=$(( $min + $y_curr + $x_curr ))

	if [ $x0 -le $x_wrap ] ; then
	  let x_next=$(( $x1 - 000000000 ))
	else
	  let x_next=$(( $x1 - $row_size ))
	fi

	# prepare link to down neighbor
	if [ $y0 -le $y_wrap ] ; then
	  let y_next=$(( $row_size * ( $y1 - 000000000 ) )) 
	else
	  let y_next=$(( $row_size * ( $y1 - $col_size ) ))
	fi

        
        if [ "$diagonal" == "0" ] ; then

	  # prepare link to right neighbor
	  if [ $x0 -le $x_wrap ] ; then
	    let right_lq=$default_lq
	    let right_rq=$default_rq
	  else
	    let right_lq=$loop_x_lq
	    let right_rq=$loop_x_rq
	  fi

	  # prepare link to down neighbor
	  if [ $y0 -le $y_wrap ] ; then
	    let down_lq=$default_lq
	    let down_rq=$default_rq
	  else
	    let down_lq=$loop_y_lq
	    let down_rq=$loop_y_rq
	  fi

	  # configure link to right neighbor
	  mlc_link_set  $ifn  $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_curr + $x_next ))   $right_lq $right_rq $purge
	  # configure link to down neighbor
	  mlc_link_set  $ifn  $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_next + $x_curr ))   $down_lq $down_rq  $purge

	else

	  if [ $x0 -le $x_wrap ] && [ $y0 -le $y_wrap ]; then
	    let right_lq=$default_lq
	    let right_rq=$default_rq
	    let down_lq=$default_lq
	    let down_rq=$default_rq
	  else
	    let right_lq=$loop_x_lq
	    let right_rq=$loop_x_rq
	    let down_lq=$loop_y_lq
	    let down_rq=$loop_y_rq
	  fi

	  # configure diagonal link to down-right neighbor
	  mlc_link_set $ifn   $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_next + $x_next ))   $right_lq $right_rq $purge
	  # configure diagonal link from right neighbor to down neighbor
	  mlc_link_set $ifn   $(( $min + $y_curr + $x_next ))  $ifn $(( $min + $y_next + $x_curr ))   $down_lq $down_rq $purge

	fi

      done
  done
}



mlc_ns3_prepare() {

    for idx in $( seq $mlc_ns3_idx_min $mlc_ns3_idx_max ) ; do
	ebtables -I FORWARD -s $mlc_mac_prefix:0:0:$idx/FF:FF:FF:0:0:FF -j ACCEPT
    done

}


mlc_ns3_connect() {

  [ -z $1 ] &&\
     echo "mlc_ns3_connect <go> [dev_idx] [min_node] [max_node] [tap-offset] [tap-prefix] [br-prefix]"  &&\
     return 1

  local idx=${2:-$mlc_ns3_idx_min}
  local min=${3:-$mlc_min_node}
  local max=${4:-$( mlc_get_max_node )}
  local tap_prefix=${5:-"NTP"}
  local br_prefix=${6:-"NBR"}
  local offset=${7:-2}

  echo "idx=$idx min=$min max=$max  tap_prefix=$tap_prefix br_prefix=$br_prefix offset=$offset"
  local node

  for node in $( seq $min $max ) ; do

      local tap_num=$(( ($node - $min) + $offset )) 
      local bridge_name="${br_prefix}${node}"
      local tap_name="${tap_prefix}${node}"
      local veth_name="$(MLC_get_veth_cache $node $idx)"

      brctl addbr $bridge_name
      brctl setfd $bridge_name 0
      ifconfig    $bridge_name up
      ifconfig    $bridge_name promisc

      ifconfig $veth_name 0.0.0.0 promisc up
      brctl addif $bridge_name $veth_name

      tunctl -t $tap_name
      ifconfig $tap_name 0.0.0.0 promisc up
      brctl addif $bridge_name $tap_name


  done


}


mlc_peer_grid() {
  [ -z $1 ] &&\
     echo "mlc_configure_grid <dev_idx> [lq] [loop_x_lq] [loop_y_lq] [0=ortographic,1=diagonal] [distance] [max_node] [min_node] [rq] [loop_x_rq] [loop_y_rq] [columns]"  &&\
     echo "example: mlc_configure_grid 1 9 0 0 0 1 119 10 # configures a grid of 2x10 nodes with links to each 1 hop-neighbor of lq=3" &&\
     echo "example: mlc_configure_grid 1                  # will do the same with all nodes and lq=3" &&\
     return 1

  local ifn=$1
  local default_lq=${2:-3}
  local loop_x_lq=${3:-0}
  local loop_y_lq=${4:-0}
  local diagonal=${5:-0}
  local distance=${6:-1}
  local max=$( mlc_get_max_node )
  local max=${7:-$max}
  local min=${8:-$mlc_min_node}
  local default_rq=${9:-$default_lq}
  local loop_x_rq=${10:-$loop_x_lq}
  local loop_y_rq=${11:-$loop_y_lq}
  local row_size=${12:-$10}

  local x_max=$(( $row_size - 1 ))
  local y_max=$(( ( ( ( $max - $min )  + 1 ) / $row_size ) - 1 )) 

  local col_size=$(( $y_max + 1 ))

  local x0 x1 y0 y1 x_wrap y_wrap x_curr y_curr curr x_next y_next right_lq down_lq right_rq down_rq

  echo "$0 ifn=$ifn lq=$default_lq/$default_rq x_lq=$loop_x_lq/$loop_x_rq y_lq=$loop_y_lq/$loop_y_rq diagonal=$diagonal distance=$distance min=$min max=$max x_max=$x_max y_max=$y_max row_size=$row_size"

  for y0 in $( seq 0 $y_max ) ; do
      let y1=$(( $y0 + $distance ))

      for x0 in $( seq 0 $x_max ) ; do
	let x1=$(( $x0 + $distance ))

        let x_wrap=$(( $x_max - $distance ))
        let y_wrap=$(( $y_max - $distance ))
        let x_curr=$x0
        let y_curr=$(( ( $row_size * $y0 ) ))
#       let curr=$(( $min + $y_curr + $x_curr ))

	if [ $x0 -le $x_wrap ] ; then
	  let x_next=$(( $x1 - 000000000 ))
	else
	  let x_next=$(( $x1 - $row_size ))
	fi

	# prepare link to down neighbor
	if [ $y0 -le $y_wrap ] ; then
	  let y_next=$(( $row_size * ( $y1 - 000000000 ) )) 
	else
	  let y_next=$(( $row_size * ( $y1 - $col_size ) ))
	fi

        
        if [ "$diagonal" == "0" ] ; then

	  # prepare link to right neighbor
	  if [ $x0 -le $x_wrap ] ; then
	    let right_lq=$default_lq
	    let right_rq=$default_rq
	  else
	    let right_lq=$loop_x_lq
	    let right_rq=$loop_x_rq
	  fi

	  # prepare link to down neighbor
	  if [ $y0 -le $y_wrap ] ; then
	    let down_lq=$default_lq
	    let down_rq=$default_rq
	  else
	    let down_lq=$loop_y_lq
	    let down_rq=$loop_y_rq
	  fi

	  # configure link to right neighbor
#	  mlc_link_set  $ifn  $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_curr + $x_next ))   $right_lq $right_rq
	  mlc_peer_set        $(( $min + $y_curr + $x_curr ))       $(( $min + $y_curr + $x_next )) 
	  # configure link to down neighbor
#	  mlc_link_set  $ifn  $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_next + $x_curr ))   $down_lq $down_rq
	  mlc_peer_set        $(( $min + $y_curr + $x_curr ))       $(( $min + $y_next + $x_curr )) 

	else

	  if [ $x0 -le $x_wrap ] && [ $y0 -le $y_wrap ]; then
	    let right_lq=$default_lq
	    let right_rq=$default_rq
	    let down_lq=$default_lq
	    let down_rq=$default_rq
	  else
	    let right_lq=$loop_x_lq
	    let right_rq=$loop_x_rq
	    let down_lq=$loop_y_lq
	    let down_rq=$loop_y_rq
	  fi

	  # configure diagonal link to down-right neighbor
#	  mlc_link_set $ifn   $(( $min + $y_curr + $x_curr ))  $ifn $(( $min + $y_next + $x_next ))   $right_lq $right_rq
	  mlc_peer_set        $(( $min + $y_curr + $x_curr ))       $(( $min + $y_next + $x_next ))  
	  # configure diagonal link from right neighbor to down neighbor
#	  mlc_link_set $ifn   $(( $min + $y_curr + $x_next ))  $ifn $(( $min + $y_next + $x_curr ))   $down_lq $down_rq
	  mlc_peer_set        $(( $min + $y_curr + $x_next ))       $(( $min + $y_next + $x_curr ))   

	fi

      done
  done
}

MLC_get_input_args() {

    if ! getopt -V | grep enhanced > /dev/null; then
      echo "Old getopt(1). You need the enhanced getopt to let this work !"
      return 1
    fi

    if ! ipcalc -v > /dev/null; then
      echo "Missing ipcalc You need ipcalc to let this work !"
      return 1
    fi

    if ! debootstrap --help > /dev/null; then
	echo "'debootstrap' command is missing"
	return 1
    fi

    # echo MLC_get_input_args $@ || return 1

    TEMP=$(getopt -o hn:p:m: --long help,name:,path:,mother:,id: -- "$@")
    if [ $? != 0 ] ; then echo "Terminating..." >&2 ; return 1 ; fi

    # Note the quotes around `$TEMP': they are essential!
    eval set -- "$TEMP"
    
    while true ; do
	    # echo evaluating $@
	    case "$1" in
		    --id) MLC_assign_networks $2 ; shift 2 ;;
		    --) shift ; break ;;
		    *) echo "Internal error!" ; return 1 ;;
	    esac
    done

    if [ "$1" != "" ] ; then echo "found illegal commands: $@" ; return 1 ; fi


    if [ ! -d "$mlc_conf_dir" ]; then
	echo "specified path to mlc configs and rootfs '$mlc_conf_dir' does not exist"
	return 1
    fi

    if [ ! -d "$mlc_path_dir" ]; then
	echo "specified path to mlc home dir: '$mlc_path_dir' does not exist"
	return 1
    fi

    if [ "$(id -u)" != "0" ]; then
	echo "This script should be run as 'root'"
	return 1
    fi 

}


MLC_configure_individual() {

    local vm_id=$1
    local vm_name="${mlc_name_prefix}${vm_id}"

    local vm_rootfs=$mlc_conf_dir/$vm_name/rootfs

    local mother_name="${mlc_name_prefix}${mlc_mother_id}"

    echo MLC_configure_individual "vm_id=$vm_id vm_name=$vm_name"

        # cp -ar $mlc_path_dir/files/* $vm_rootfs
        # http://stackoverflow.com/questions/2193584/copy-folder-recursively-excluding-some-folders 
        # putting things in files/usr/ does not work because it'll be overmounted anyway!

    if [ "$vm_name" == "$mother_name" ] ; then
	rsync -av --exclude='.svn' --exclude='.git' $mlc_path_dir/files/* $vm_rootfs/
    else
	rsync -av --exclude='.svn' --exclude='.git' $mlc_path_dir/files/etc $vm_rootfs/
    fi

  mkdir -p $vm_rootfs/etc/config

    # set the hostname
    cat <<EOF > $vm_rootfs/etc/hostname
$vm_name
EOF

# set the nameserver
cat <<EOF > $mother_rootfs/etc/resolv.conf
nameserver $mlc_dns
EOF

    # configure the network using static IPs
    cat <<EOF > $vm_rootfs/etc/network/interfaces

auto lo
iface lo inet loopback

auto  $mlc_net0_name
iface $mlc_net0_name inet static
  address $mlc_net0_ip4_addr
  netmask $mlc_net0_ip4_mask
  broadcast $mlc_net0_ip4_brc
  mtu $mlc_net_mtu
  up route add default gw $mlc_net0_ip4_gw


#########################################################
#########################################################
# MESH interfaces:

auto  $mlc_net1_name
iface $mlc_net1_name inet static
  mtu $mlc_net_mtu

auto  $mlc_net11_name
iface $mlc_net11_name inet static
  address $mlc_net11_ip4_addr
  netmask $mlc_net11_ip4_mask
  broadcast $mlc_net11_ip4_brc
  vlan_raw_device $mlc_net1_name
  up /sbin/ip -6 addr add $mlc_net11_ula_addr/$mlc_net11_ula_mask dev $mlc_net11_name
#  up /sbin/ip -6 addr add $mlc_net11_rip_addr/$mlc_net11_rip_mask dev $mlc_net11_name

auto  $mlc_net12_name
iface $mlc_net12_name inet static
  address $mlc_net12_ip4_addr
  netmask $mlc_net12_ip4_mask
  broadcast $mlc_net12_ip4_brc
  vlan_raw_device $mlc_net1_name
  up /sbin/ip -6 addr add $mlc_net12_ula_addr/$mlc_net12_ula_mask dev $mlc_net12_name
#  up /sbin/ip -6 addr add $mlc_net12_rip_addr/$mlc_net12_rip_mask dev $mlc_net12_name

#
auto  $mlc_net13_name
iface $mlc_net13_name inet static
  address $mlc_net13_ip4_addr
  netmask $mlc_net13_ip4_mask
  broadcast $mlc_net13_ip4_brc
  vlan_raw_device $mlc_net1_name
  up /sbin/ip -6 addr add $mlc_net13_ula_addr/$mlc_net13_ula_mask dev $mlc_net13_name
##  up /sbin/ip -6 addr add $mlc_net13_rip_addr/$mlc_net13_rip_mask dev $mlc_net13_name


auto  $mlc_net2_name
iface $mlc_net2_name inet static
  mtu $mlc_net_mtu

#auto  $mlc_net21_name
#iface $mlc_net21_name inet static
#  address $mlc_net21_ip4_addr
#  netmask $mlc_net21_ip4_mask
#  broadcast $mlc_net21_ip4_brc
#  vlan_raw_device $mlc_net2_name
#  up /sbin/ip -6 addr add $mlc_net21_ula_addr/$mlc_net21_ula_mask dev $mlc_net21_name
##  up /sbin/ip -6 addr add $mlc_net21_rip_addr/$mlc_net21_rip_mask dev $mlc_net21_name
#
#auto  $mlc_net22_name
#iface $mlc_net22_name inet static
#  address $mlc_net22_ip4_addr
#  netmask $mlc_net22_ip4_mask
#  broadcast $mlc_net22_ip4_brc
#  vlan_raw_device $mlc_net2_name
#  up /sbin/ip -6 addr add $mlc_net22_ula_addr/$mlc_net22_ula_mask dev $mlc_net22_name
##  up /sbin/ip -6 addr add $mlc_net22_rip_addr/$mlc_net22_rip_mask dev $mlc_net22_name
#
#auto  $mlc_net23_name
#iface $mlc_net23_name inet static
#  address $mlc_net23_ip4_addr
#  netmask $mlc_net23_ip4_mask
#  broadcast $mlc_net23_ip4_brc
#  vlan_raw_device $mlc_net2_name
#  up /sbin/ip -6 addr add $mlc_net23_ula_addr/$mlc_net23_ula_mask dev $mlc_net23_name
##  up /sbin/ip -6 addr add $mlc_net23_rip_addr/$mlc_net23_rip_mask dev $mlc_net23_name



EOF


    # configure the network using static IPs (DISABLED)
    cat <<EOF > /dev/zero

#########################################################
#########################################################
# NS3 experimental interfaces:

auto  $mlc_net3_name
iface $mlc_net3_name inet static
  mtu $mlc_net_mtu

  address $mlc_net3_ip4_addr
  netmask $mlc_net3_ip4_mask
  broadcast $mlc_net3_ip4_brc
  up /sbin/ip -6 addr add $mlc_net3_ula_addr/$mlc_net3_ula_mask dev $mlc_net3_name

#auto  $mlc_net31_name
#iface $mlc_net31_name inet static
#  address $mlc_net31_ip4_addr
#  netmask $mlc_net31_ip4_mask
#  broadcast $mlc_net31_ip4_brc
#  vlan_raw_device $mlc_net3_name
#  up /sbin/ip -6 addr add $mlc_net31_ula_addr/$mlc_net31_ula_mask dev $mlc_net31_name
#
#auto  $mlc_net32_name
#iface $mlc_net32_name inet static
#  address $mlc_net32_ip4_addr
#  netmask $mlc_net32_ip4_mask
#  broadcast $mlc_net32_ip4_brc
#  vlan_raw_device $mlc_net3_name
#  up /sbin/ip -6 addr add $mlc_net32_ula_addr/$mlc_net32_ula_mask dev $mlc_net32_name


#########################################################
#########################################################
# peering interfaces:


auto  $mlc_net4_name
iface $mlc_net4_name inet static
  mtu $mlc_net_mtu

auto  $mlc_net41_name
iface $mlc_net41_name inet static
  address $mlc_net41_ip4_addr
  netmask $mlc_net41_ip4_mask
  broadcast $mlc_net41_ip4_brc
  vlan_raw_device $mlc_net4_name
  up /sbin/ip -6 addr add $mlc_net41_ula_addr/$mlc_net41_ula_mask dev $mlc_net41_name

auto  $mlc_net42_name
iface $mlc_net42_name inet static
  address $mlc_net42_ip4_addr
  netmask $mlc_net42_ip4_mask
  broadcast $mlc_net42_ip4_brc
  vlan_raw_device $mlc_net4_name
  up /sbin/ip -6 addr add $mlc_net42_ula_addr/$mlc_net42_ula_mask dev $mlc_net42_name


auto  $mlc_net5_name
iface $mlc_net5_name inet static
  mtu $mlc_net_mtu

auto  $mlc_net51_name
iface $mlc_net51_name inet static
  address $mlc_net51_ip4_addr
  netmask $mlc_net51_ip4_mask
  broadcast $mlc_net51_ip4_brc
  vlan_raw_device $mlc_net5_name
  up /sbin/ip -6 addr add $mlc_net51_ula_addr/$mlc_net51_ula_mask dev $mlc_net51_name

auto  $mlc_net52_name
iface $mlc_net52_name inet static
  address $mlc_net52_ip4_addr
  netmask $mlc_net52_ip4_mask
  broadcast $mlc_net52_ip4_brc
  vlan_raw_device $mlc_net5_name
  up /sbin/ip -6 addr add $mlc_net52_ula_addr/$mlc_net52_ula_mask dev $mlc_net52_name


auto  $mlc_net6_name
iface $mlc_net6_name inet static
  mtu $mlc_net_mtu

auto  $mlc_net61_name
iface $mlc_net61_name inet static
  address $mlc_net61_ip4_addr
  netmask $mlc_net61_ip4_mask
  broadcast $mlc_net61_ip4_brc
  vlan_raw_device $mlc_net6_name
  up /sbin/ip -6 addr add $mlc_net61_ula_addr/$mlc_net61_ula_mask dev $mlc_net61_name

auto  $mlc_net62_name
iface $mlc_net62_name inet static
  address $mlc_net62_ip4_addr
  netmask $mlc_net62_ip4_mask
  broadcast $mlc_net62_ip4_brc
  vlan_raw_device $mlc_net6_name
  up /sbin/ip -6 addr add $mlc_net62_ula_addr/$mlc_net62_ula_mask dev $mlc_net62_name


auto  $mlc_net7_name
iface $mlc_net7_name inet static
  mtu $mlc_net_mtu

auto  $mlc_net71_name
iface $mlc_net71_name inet static
  address $mlc_net71_ip4_addr
  netmask $mlc_net71_ip4_mask
  broadcast $mlc_net71_ip4_brc
  vlan_raw_device $mlc_net7_name
  up /sbin/ip -6 addr add $mlc_net71_ula_addr/$mlc_net71_ula_mask dev $mlc_net71_name

auto  $mlc_net72_name
iface $mlc_net72_name inet static
  address $mlc_net72_ip4_addr
  netmask $mlc_net72_ip4_mask
  broadcast $mlc_net72_ip4_brc
  vlan_raw_device $mlc_net7_name
  up /sbin/ip -6 addr add $mlc_net72_ula_addr/$mlc_net72_ula_mask dev $mlc_net72_name



EOF


    # configure bmxd
    cat <<EOF > $vm_rootfs/etc/config/bmx

config 'bmx' 'general'

	option 'ogm_interval' '500'
	option 'aggreg_interval' '200'

	option 'dbg_mute_timeout' '0'

	option 'http_info_port' '8099'
	option 'http_info_global_access' '1'

config 'plugin'
	option 'plugin' 'bmx_http_info.so'
	
config 'dev'
	option 'dev' "${mlc_dev_prefix}1" #
	option 'linklayer' '2'
        option 'clone' '200'
	
config 'dev'
	option 'dev' "${mlc_dev_prefix}2"
	option 'linklayer' '2'
        option 'clone' '200'

EOF


# configure babeld
cat <<EOF > $vm_rootfs/etc/babeld.conf 

## http://battlemesh.org/BattleMeshV4/NodeConfig
## http://lists.alioth.debian.org/pipermail/babel-users/2008-March/000074.html

redistribute local if $mlc_net13_name ip $mlc_ip6_ula3_prefix::/48 ge 48
redistribute local if $mlc_net23_name ip $mlc_ip6_ula3_prefix::/48 ge 48
redistribute local deny
redistribute deny

EOF

# configure bmx6
cat <<EOF > $vm_rootfs/etc/config/bmx6

config 'bmx6' 'general'
        option 'tunOutTimeout' '5000'

config 'plugin'
        option 'plugin' 'bmx6_config.so'

config 'plugin'
        option 'plugin' 'bmx6_json.so'

config 'plugin'
       option 'plugin' 'bmx6_sms.so'

config 'plugin'
        option 'plugin' 'bmx6_table.so'

config 'plugin'
        option 'plugin' 'bmx6_topology.so'

#config 'ipVersion'
#       option 'ipVersion' '6'
#       option 'throwRules' '0'
#	option tableTuns 61
#	option tablePrefTuns 6001

config dev
#	option dev $mlc_net12_name
	option dev $mlc_net1_name

config 'tunDev' default
        option 'tunDev' 'default'
        option tun6Address $mlc_ip6_ripe2_prefix:$vm_id::1/64
        option tun4Address 10.$(( ( $vm_id / 100 ) )).$(( $vm_id % 100 )).1/24

config 'tunOut' ip6
        option 'tunOut' 'ip6'
        option 'network' '$mlc_ip6_ripe2_prefix::/16'
#        option 'exportDistance' '0'
#        option 'ipMetric' '2000'

config 'tunOut' ip4
        option 'tunOut' 'ip4'
        option 'network' '10.10.0.0/16'
#        option 'ipMetric' '2000'


config 'redistTable'
        option 'redistTable' 'bla'
        option 'table' '100'
        option 'all' '1'
        option 'sys' '60'

config 'redistTable'
        option 'redistTable' 'myBird'
        option 'table' '100'
        option 'all' '1'
        option 'sys' '12'

EOF


# configure bmx7
cat <<EOF > $vm_rootfs/etc/config/bmx7

#config 'bmx7' 'general'
#        option 'trustedNodesDir' '/etc/bmx7/trustedNodes'
#        option 'tunOutTimeout' '5000'
#        option 'descCompression' '1'

config 'plugin'
        option 'plugin' 'bmx7_config.so'

#config 'plugin'
#        option 'plugin' 'bmx7_json.so'

config 'plugin'
       option 'plugin' 'bmx7_sms.so'

config 'plugin'
        option 'plugin' 'bmx7_tun.so'

config 'plugin'
        option 'plugin' 'bmx7_topology.so'

#config 'plugin'
#        option 'plugin' 'bmx7_iwinfo.so'

config 'plugin'
        option 'plugin' 'bmx7_table.so'

#config 'ipVersion'
#       option 'ipVersion' '6'
#       option 'throwRules' '0'
#	option tableTuns 61
#	option tablePrefTuns 6001

config dev
#	option dev $mlc_net12_name
	option dev $mlc_net1_name

#config dev
#	option dev $mlc_net2_name

config 'unicastHna'
        option 'unicastHna' $mlc_ip6_ripe3_prefix:$vm_id::/64

config 'tunDev' default
        option 'tunDev' 'default'
        option tun6Address $mlc_ip6_ripe3_prefix:$vm_id::1/64
        option tun4Address 10.20.$(( $vm_id % 100 )).1/24

config 'tunOut' ip6
        option 'tunOut' 'ip6'
        option 'network' '$mlc_ip6_ripe3_prefix::/16'
#        option 'exportDistance' '0'
#        option 'ipMetric' '2000'

config 'tunOut' ip4
        option 'tunOut' 'ip4'
        option 'network' '10.20.0.0/16'
#        option 'ipMetric' '2000'


#config 'redistTable'
#        option 'redistTable' 'bla'
#        option 'table' '110'
#        option 'all' '1'
#        option 'sys' '60'

#config 'redistTable'
#        option 'redistTable' 'myBird'
#        option 'table' '110'
#        option 'all' '1'
#        option 'sys' '12'

EOF



cat <<EOF > /dev/null


config dev
#	option dev $mlc_net22_name
	option dev $mlc_net2_name
#	option announce 1

#config unicastHna
#        option unicastHna $mlc_ip6_ripe2_prefix:$vm_id::/64

config 'redistribute' 'guifi'
        option 'redistribute' 'guifi'
        option 'connect' '1'
        option 'network' '10.0.0.0/8'
        option 'bandwidth' '10000'

config 'tunOut' ip6default
        option 'tunOut' 'ip6default'
        option 'network' '::/0'
        option 'ipMetric' '3000'
        option 'maxPrefixLen' '0'


config 'syncSms'
        option 'syncSms' 'test'


EOF
  


# configure olsrd
cat <<EOF > $vm_rootfs/etc/olsrd.conf

IpVersion 6
RtTable        90

LoadPlugin "olsrd_txtinfo.so.0.1"
{
PlParam "port" "8080"
#PlParam "Host" "127.0.0.1"
PlParam "Net" "0.0.0.0 0.0.0.0"
}

Interface "$mlc_net11_name"
{
    IPv6Src $mlc_net11_ula_addr
    IPv6Multicast       FF0E::1
}

Interface "$mlc_net21_name"
{
    IPv6Src $mlc_net21_ula_addr
    IPv6Multicast       FF0E::1
}


EOF



    return 0
}






MLC_create_lxc_config()
{
    local node_name=$1

    local child_rootfs=$mlc_conf_dir/$node_name/rootfs
    local child_config=$mlc_conf_dir/$node_name
    local mother_name="${mlc_name_prefix}${mlc_mother_id}"
    local mother_rootfs=$mlc_conf_dir/$mother_name/rootfs

    echo "MLC_create_lxc_config() node_name=$node_name child_rootfs=$child_rootfs child_config=$child_config mother_name=$mother_name mother_rootfs=$mother_rootfs"

    
    mkdir -p $child_config
    [ -f $child_config/config.old ] && mv -f $child_config/config.old $child_config/config.old.old
    [ -f $child_config/config ] && mv -f $child_config/config $child_config/config.old


    cat <<EOF > $child_config/config

##########################################################
# Container specific configuration
lxc.utsname = $node_name
lxc.arch = $mlc_arch
lxc.rootfs = $child_rootfs
lxc.rootfs.backend = dir

lxc.network.type = veth
lxc.network.flags = up
lxc.network.link = $mlc_net0_link
lxc.network.name = $mlc_net0_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net0_mac
lxc.network.veth.pair = $mlc_net0_veth

lxc.network.type = veth
lxc.network.flags = up
lxc.network.link = $mlc_net1_link
lxc.network.name = $mlc_net1_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net1_mac
lxc.network.veth.pair = $mlc_net1_veth

#lxc.network.type = veth
#lxc.network.flags = up
#lxc.network.link = $mlc_net2_link
#lxc.network.name = $mlc_net2_name
#lxc.network.mtu = $mlc_net_mtu
#lxc.network.hwaddr = $mlc_net2_mac
#lxc.network.veth.pair = $mlc_net2_veth


# Common configuration
# lxc.include = /usr/share/lxc/config/debian.common.conf
##########################################################
# Copied from /share/lxc/config/debian.common.conf
# This derives from the global common config  
# lxc.include = /usr/share/lxc/config/common.conf
##########################################################
# Copied from /usr/share/lxc/config/common.conf
# Default configuration shared by all containers

# Setup the LXC devices in /dev/lxc/
lxc.devttydir = lxc

# Allow for 1024 pseudo terminals
lxc.pts = 1024

# Setup 4 tty devices
lxc.tty = 4

# Drop some harmful capabilities
lxc.cap.drop = mac_admin mac_override sys_time sys_module sys_rawio

# Set the pivot directory
lxc.pivotdir = lxc_putold

# Ensure hostname is changed on clone
lxc.hook.clone = /usr/share/lxc/hooks/clonehostname

# CGroup whitelist
lxc.cgroup.devices.deny = a
## Allow any mknod (but not reading/writing the node)
lxc.cgroup.devices.allow = c *:* m
lxc.cgroup.devices.allow = b *:* m
## Allow specific devices
### /dev/null
lxc.cgroup.devices.allow = c 1:3 rwm
### /dev/zero
lxc.cgroup.devices.allow = c 1:5 rwm
### /dev/full
lxc.cgroup.devices.allow = c 1:7 rwm
### /dev/tty
lxc.cgroup.devices.allow = c 5:0 rwm
### /dev/console
lxc.cgroup.devices.allow = c 5:1 rwm
### /dev/ptmx
lxc.cgroup.devices.allow = c 5:2 rwm
### /dev/random
lxc.cgroup.devices.allow = c 1:8 rwm
### /dev/urandom
lxc.cgroup.devices.allow = c 1:9 rwm
### /dev/pts/*
lxc.cgroup.devices.allow = c 136:* rwm
### fuse
lxc.cgroup.devices.allow = c 10:229 rwm

# Setup the default mounts
lxc.mount.auto = cgroup:mixed proc:mixed sys:mixed
lxc.mount.entry = /sys/fs/fuse/connections sys/fs/fuse/connections none bind,optional 0 0

# Blacklist some syscalls which are not safe in privileged
# containers
lxc.seccomp = /usr/share/lxc/config/common.seccomp

# Lastly, include all the configs from /usr/share/lxc/config/common.conf.d/
# lxc.include = /usr/share/lxc/config/common.conf.d/
##########################################################
# Copied from /usr/share/lxc/config/common.conf.d/00-lxcfs.conf
lxc.hook.mount = /usr/share/lxcfs/lxc.mount.hook
lxc.hook.post-stop = /usr/share/lxcfs/lxc.reboot.hook
##########################################################

# Doesn't support consoles in /dev/lxc/
lxc.devttydir =

# When using LXC with apparmor, the container will be confined by default.
# If you wish for it to instead run unconfined, copy the following line
# (uncommented) to the container's configuration file.
#lxc.aa_profile = unconfined

# If you wish to allow mounting block filesystems, then use the following
# line instead, and make sure to grant access to the block device and/or loop
# devices below in lxc.cgroup.devices.allow.
#lxc.aa_profile = lxc-container-default-with-mounting

# Extra cgroup device access
## rtc
lxc.cgroup.devices.allow = c 254:0 rm
## tun
lxc.mount.entry = /dev/net dev/net none bind,create=dir
lxc.cgroup.devices.allow = c 10:200 rwm
# lxc.hook.autodev = sh -c "modprobe tun; mkdir $child_rootfs/dev/net; mknod $child_rootfs/dev/net/tun c 10 200; chmod 0666 $child_rootfs/dev/net/tun"
## hpet
lxc.cgroup.devices.allow = c 10:228 rwm
## kvm
lxc.cgroup.devices.allow = c 10:232 rwm
## To use loop devices, copy the following line to the container's
## configuration file (uncommented).
#lxc.cgroup.devices.allow = b 7:* rwm
##########################################################



## consoles
#lxc.cgroup.devices.allow = c 4:0 rwm
#lxc.cgroup.devices.allow = c 4:1 rwm

#lxc.mount.entry=proc   $mother_rootfs/proc proc nodev,noexec,nosuid 0 0
#lxc.mount.entry=devpts $mother_rootfs/dev/pts devpts defaults 0 0
#lxc.mount.entry=sysfs  $mother_rootfs/sys sysfs defaults  0 0

EOF


    
    if [ $? -ne 0 ]; then
	echo "Failed to add configuration"
	return 1
    fi

    if [ "$mother_rootfs" ] && [ "$node_name" != "$mother_name" ] ; then
	for dir in $mlc_mount_dirs; do
	    cat <<EOF >> $child_config/config
# lxc.mount.entry=$mother_rootfs/$dir $child_rootfs/$dir none ro,bind 0 0
lxc.mount.entry=$mother_rootfs/$dir $dir none ro,bind 0 0
EOF
	    if [ $? -ne 0 ]; then
		echo "failed to attach $dir mount entry to lxc configuration file: $child_config"
		return 1
	    fi
	done
    fi

    cat <<EOF >> /dev/zero 
# $child_config/config

lxc.network.type = veth
lxc.network.flags = up
lxc.network.name = $mlc_net3_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net3_mac
lxc.network.veth.pair = $mlc_net3_veth

lxc.network.type = veth
lxc.network.flags = up
lxc.network.name = $mlc_net4_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net4_mac
lxc.network.veth.pair = $mlc_net4_veth

lxc.network.type = veth
lxc.network.flags = up
lxc.network.name = $mlc_net5_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net5_mac
lxc.network.veth.pair = $mlc_net5_veth

lxc.network.type = veth
lxc.network.flags = up
lxc.network.name = $mlc_net6_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net6_mac
lxc.network.veth.pair = $mlc_net6_veth

lxc.network.type = veth
lxc.network.flags = up
lxc.network.name = $mlc_net7_name
lxc.network.mtu = $mlc_net_mtu
lxc.network.hwaddr = $mlc_net7_mac
lxc.network.veth.pair = $mlc_net7_veth

EOF

    return 0
}



mlc_update_individual() {

    if [ -z $1 ] ; then
	echo "mlc_update_individual <node-id-number> [custom-config.sh]"
	return 1
    fi


    local node_id=$1
    local node_name=$mlc_name_prefix$node_id

    local mother_name="${mlc_name_prefix}${mlc_mother_id}"

    if ! lxc-info -n $node_name | grep STOPPED ; then 
	echo "WARNING: specified container $node_name is RUNNING"
    fi

    local child_rootfs=$mlc_conf_dir/$node_name/rootfs
    local child_config=$mlc_conf_dir/$node_name
    local mother_rootfs=$mlc_conf_dir/$mother_name/rootfs

    MLC_assign_networks $node_id

    if ! [ -d "$child_rootfs" ]; then
	echo "childs rootfs: '$child_rootfs' does not exist !!!"
	return 1
    fi

    echo configuring $child_rootfs $node_id $(( $node_id % 100 )) $(( $node_id / 100 )) 


    MLC_configure_individual $node_id
    if [ $? -ne 0 ]; then
	echo "failed to configure $child_rootfs"; return 1
    fi

    MLC_create_lxc_config  $node_name
    if [ $? -ne 0 ]; then
	echo "failed write childs configuration file: $child_config"; return 1
    fi

  
}



MLC_install_child()
{
  local child_rootfs=$1
  local mother_rootfs=$2

  echo "MLC_install_child   child_rootfs=$child_rootfs mother_rootfs=$mother_rootfs"

  
  mkdir -p $child_rootfs/

  for dir in $mlc_empty_dirs; do
    mkdir -p $child_rootfs/$dir
  done
  
  
  for dir in $mlc_mount_dirs; do
    mkdir -p $child_rootfs/$dir
  done

  for dir in $mlc_copy_dirs; do
    cp -ar $mother_rootfs/$dir $child_rootfs/$dir
    if [ $? -ne 0 ]; then
	echo "Failed to copy mother rootfs: $mother_rootfs"
	return 1
    fi
  done

  if false; then

      find $vm_rootfs/root/fifo0 > /dev/null 2>&1 || mkfifo $vm_rootfs/root/fifo0
      find $vm_rootfs/root/fifo1 > /dev/null 2>&1 || mkfifo $vm_rootfs/root/fifo1
  
      if echo "$mlc_arch" | grep "64"  ; then
	  ln -s /lib $child_rootfs/lib64
      fi

      chmod 755 $child_rootfs/*
      chmod 777 $child_rootfs/tmp

      chmod 777 $child_rootfs/var/tmp

      chmod 777 $child_rootfs/var/local
      chmod g+s $child_rootfs/var/local
      chgrp staff $child_rootfs/var/local

      chmod 777 $child_rootfs/var/lock
      chmod o+t $child_rootfs/var/lock
      
      chmod g+ws $child_rootfs/var/mail
  fi
  
  return 0
}



mlc_create_child() {

    if [ -z $1 ] ; then
	echo "mlc_create_child <node-id-number>"
	return 1
    fi

	local child_id="$1"
	local child_name="${mlc_name_prefix}${child_id}"
	local child_rootfs="$mlc_conf_dir/$child_name/rootfs"
	local child_config="$mlc_conf_dir/$child_name"
	local mother_name="${mlc_name_prefix}${mlc_mother_id}"
	local mother_rootfs="$mlc_conf_dir/$mother_name/rootfs"
	local mother_config="$mlc_conf_dir/$mother_name/config"


        time MLC_assign_networks $child_id


	if lxc-info -n $child_name 2>&1 | grep RUNNING ; then 
	    echo "specified container '$child_name' must be stopped first"; return 1
	fi

	if [ -d "$child_rootfs" ]; then
	    echo "childs rootfs: '$child_rootfs' does already exist"; return 1
	fi

	if [ -d "$child_config" ]; then
	    echo "childs config:'$child_config' does already exist"; return 1
	fi

	if [ ! -d "$mother_rootfs" ]; then
	    echo "mother rootfs: '$mother_rootfs' does not exist"; return 1
	fi


	if [ ! -f "$mother_config" ]; then
	    echo "mother config:'$mother_config' does not exist"; return 1
	fi



	time MLC_install_child $child_rootfs $mother_rootfs
	if [ $? -ne 0 ]; then
	    echo "failed to install child fs"; return 1
	fi

	time MLC_configure_individual $child_id
	if [ $? -ne 0 ]; then
	    echo "failed to configure child debian for a container"; return 1
	fi


	time MLC_create_lxc_config $child_name
	if [ $? -ne 0 ]; then
	    echo "failed write childs configuration file: $child_config"; return 1
	fi
	
	echo done
}



mlc_destroy() {

    if [ -z $1 ] ; then
	echo "mlc_create_child <node-id-number>"
	return 1
    fi

	local child_id="$1"
	local child_name="${mlc_name_prefix}${child_id}"

	MLC_assign_networks $child_id

	if lxc-info -n $child_name | grep RUNNING ; then
	    echo "specified container $child_name must be stopped first"; return 1
	fi


	local vm_rootfs=$mlc_conf_dir/$child_name/rootfs
	local vm_config=$mlc_conf_dir/$child_name


	if [ ! -d "$vm_config" ]; then
	    echo "config for '$vm_config' does not exist"
	else
	    rm -r --preserve-root $vm_config
	fi
}



mlc_perf() {
#    set -x
        local child_id="$1"
        local process_name="$2"
        local perf_time="$3"
        local repeat="$4"
        local selections=${5:-u}

        local child_name="${mlc_name_prefix}${child_id}"
        local process_pid=$(lxc-ps -n $child_name -- aux | grep "$process_name" | awk '{print $3}')
        local perf_log_dir="/tmp/mlc_perfs"
        local perf_log_name="$child_name.$process_pid.log"
        local perf_log_path="$perf_log_dir/$perf_log_name"
        
        local i=0

        if [ "$process_pid" ]; then
            mkdir -p $perf_log_dir

            while ! [ "$repeat" ] || [ "$repeat" == "0" ] || [ $i -lt $repeat ]; do

                local pstart=$(ps aux | grep -v "grep" | grep "$process_name" | wc -l)
            
#               timeout -s INT $perf_time perf stat -a -e task-clock,cycles,instructions --pid $process_pid 2>$perf_log_path
#               perf stat -a -e instructions:$selections --pid $process_pid sleep $perf_time 2>$perf_log_path
                timeout -s INT $perf_time perf stat -a -e instructions:$selections --pid $process_pid 2>$perf_log_path

                # cat $perf_log_path

                local pend=$(ps aux | grep -v "grep" | grep "$process_name" | wc -l)
                local ips=$((( $(cat $perf_log_path| grep instructions | awk '{print $1}' | sed s/,//g ) / $perf_time )))

                printf "%10s  %3s %3s\n" $ips $pstart $pend

                i=$((( $i + 1 )))

                if ! [ "$repeat" ]; then
                    break
                fi
            done
        fi
        
}

