#!/bin/bash
# set -x


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

mother_name="${mlc_name_prefix}${mlc_mother_id}"

mother_config="$mlc_conf_dir/$mother_name"
mother_rootfs="$mlc_conf_dir/$mother_name/rootfs"

MLC_assign_networks $mlc_mother_id

echo "input returned $? and  mlc_conf_dir=$mlc_conf_dir mother_name=$mother_name"

printf "\n"
printf "creating %s in %s\n" $mother_name $mother_config


export SUITE="$mlc_debian_suite"
export ARCH="$mlc_arch"

mkdir -p $mother_config
$mlc_path_dir/mlc-debian.sh -p $mother_config




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


# set the nameserver
cat <<EOF > $mother_rootfs/etc/resolv.conf
nameserver $mlc_dns
EOF



# reconfigure some services

# remove pointless services in a container
#chroot $mother_rootfs /usr/sbin/update-rc.d -f umountfs remove
#chroot $mother_rootfs /usr/sbin/update-rc.d -f hwclock.sh remove
#chroot $mother_rootfs /usr/sbin/update-rc.d -f hwclockfirst.sh remove

    
# set the root passwd:
if [ -z $mlc_passwd ] ; then
    chroot $mother_rootfs /usr/bin/passwd -d root
else
    echo -e "$mlc_passwd\n$mlc_passwd" | chroot $mother_rootfs /usr/bin/passwd
fi

# configure the public key:
mkdir -p $mother_rootfs/root/.ssh
cat <<EOF >  $mother_rootfs/root/.ssh/authorized_keys
$mlc_pub_key
EOF


# add /dev/net/tun
mkdir -p $mother_rootfs/dev/net
mknod $mother_rootfs/dev/net/tun c 10 200

# add desired debian packages:
printf "\ninstalling debian-package: %s\n" "$mlc_deb_packages"
chroot $mother_rootfs apt-get update
chroot $mother_rootfs apt-get install aptitude
chroot $mother_rootfs aptitude update
chroot $mother_rootfs aptitude upgrade
chroot $mother_rootfs aptitude install $mlc_deb_packages


# add source packages:
mkdir -p $mother_rootfs/usr/src

for src in $mlc_sources; do
  wget -c --tries=10 --directory-prefix=$mother_rootfs/usr/src $src
  if [ $? -ne 0 ]; then
      echo "Failed to download source $src"
      return 1
  fi
done

for project in $mlc_gits; do
    project_name="$(echo $project | awk -F'::' '{print $1}')"
    project_repo="$(echo $project | awk -F'::' '{print $2}')"
    
    git clone  $project_repo $mother_rootfs/usr/src/$project_name
    if [ $? -ne 0 ]; then
	echo "Failed to download git $project_repo"
	return 1
    fi
done


MLC_create_lxc_config  $mother_rootfs $mother_config

#cat <<EOF >> $mother_config/config
#lxc.mount.entry=proc   $mother_rootfs/proc proc nodev,noexec,nosuid 0 0
#lxc.mount.entry=devpts $mother_rootfs/dev/pts devpts defaults 0 0
#lxc.mount.entry=sysfs  $mother_rootfs/sys sysfs defaults  0 0
#EOF

mv $mother_rootfs/etc/network/run $mother_rootfs/etc/network/run.orig
mkdir -p $mother_rootfs/etc/network/run

MLC_configure_individual ${mlc_mother_id}

