#!/bin/bash

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

set -x
set -e

apt-get update
apt-get install aptitude 
aptitude update
aptitude upgrade
aptitude install lxc1 lxc-templates ipcalc ebtables bridge-utils


if [ -f ./mlc-vars.sh ] ; then
    . ./mlc-vars.sh
else
    echo "could not find mlc-vars.sh in $(pwd)"; exit 1
fi

mother_name="${mlc_name_prefix}${mlc_mother_id}"

mother_config="$mlc_conf_dir/$mother_name"
mother_rootfs="$mlc_conf_dir/$mother_name/rootfs"

MLC_assign_networks $mlc_mother_id

echo "input returned $? and  mlc_conf_dir=$mlc_conf_dir mother_name=$mother_name"

printf "\n"
printf "creating %s in %s\n" $mother_name $mother_config


#export SUITE="$mlc_debian_suite"
#export ARCH="$mlc_arch"

lxc-stop -n $mother_name -k || echo "already stopped"
rm -rf $mother_config

mkdir -p $mother_config
lxc-create -n $mother_name -t debian -P $mlc_conf_dir -- --arch=$mlc_arch --release=$mlc_debian_suite --enable-non-free --packages=$(echo $mlc_deb_packages | sed 's/ /,/g')


MLC_configure_individual $mlc_mother_id
if [ $? -ne 0 ]; then
    echo "failed to configure $child_rootfs"; return 1
fi

MLC_create_lxc_config  $mother_name
if [ $? -ne 0 ]; then
    echo "failed write childs configuration file: $child_config"; return 1
fi


####################################################
# reconfigure some services

# remove pointless services in a container
#chroot $mother_rootfs /usr/sbin/update-rc.d -f umountfs remove
#chroot $mother_rootfs /usr/sbin/update-rc.d -f hwclock.sh remove
#chroot $mother_rootfs /usr/sbin/update-rc.d -f hwclockfirst.sh remove


####################################################
####################################################

./mlc-init-host.sh
#lxc-start  -n $mother_name

lxc-attach -n $mother_name aptitude update
lxc-attach -n $mother_name -- aptitude --assume-yes upgrade


####################################################
# by default setup root password with no password
cat <<EOF > $mother_rootfs/etc/ssh/sshd_config
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
UseDNS no
EOF



    
# set the root passwd:
if [ -z $mlc_passwd ] ; then
    chroot $mother_rootfs /usr/bin/passwd -d root
else
    echo -e "$mlc_passwd\n$mlc_passwd" | chroot $mother_rootfs /usr/bin/passwd
#   echo -e "$mlc_passwd\n$mlc_passwd" | lxc-attach -n $mother_name passwd
fi

# configure the public key:
mkdir -p $mother_rootfs/root/.ssh
cat <<EOF >  $mother_rootfs/root/.ssh/authorized_keys
$mlc_pub_key
EOF


lxc-attach -n $mother_name -- /etc/init.d/ssh restart


for project in $mlc_sources; do
    project_name="$(echo $project | awk -F'::' '{print $1}')"
    project_repo="$(echo $project | awk -F'::' '{print $2}')"
    lxc-attach -n $mother_name -- wget -c --tries=10 --directory-prefix=/usr/src $project_repo
    lxc-attach -n $mother_name -- tar -C /usr/src -xzvf /usr/src/$project_name.tar.gz ||\
    lxc-attach -n $mother_name -- tar -C /usr/src -xzvf /usr/src/$project_name-gpl.tgz
    lxc-attach -n $mother_name -- make clean all install -C /usr/src/$project_name WOPTS="-pedantic -Wall"
done

for project in $mlc_gits; do
    project_name="$(echo $project | awk -F'::' '{print $1}')"
    project_repo="$(echo $project | awk -F'::' '{print $2}')"
    
    lxc-attach -n $mother_name -- git clone $project_repo usr/src/$project_name
    lxc-attach -n $mother_name -- git -C usr/src/$project_name checkout bmx7
    lxc-attach -n $mother_name -- make -C /usr/src/$project_name clean_all build_all install_all EXTRA_CFLAGS="-pg -DPROFILING -DCORE_LIMIT=20000 -DTRAFFIC_DUMP -DCRYPTLIB=MBEDTLS_2_4_0"
done

true
false
false





