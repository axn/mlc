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

if true; then
    apt-get update
    apt-get install aptitude 
    aptitude update
    aptitude upgrade
    aptitude install --assume-yes lxc1 lxc-templates ipcalc ebtables bridge-utils wireshark screen git-core openssh-server emacs cpufrequtils
fi


if true; then
    if [ -f /etc/screenrc ] && ! grep -qe "screen /bin/bash" /etc/screenrc; then
	cat <<EOF >> /etc/screenrc
term xterm-256color
screen
screen /bin/bash -c 'screen -X caption always " %{Wk}%?%F%{WK}%? %n %t %h %{r}\$STY@%H  %{g}%c:%s %d/%m/%y  %{w}%w %{R}%u"'
EOF
    fi
 
#    hostname MLC
    if ! [ -f ~/.ssh/id_rsa ]; then
	ssh-keygen -f ~/.ssh/id_rsa -P ""
    fi

    echo "use password: 'mlc'. And type enter for all other questions."
    adduser mlc || true
    adduser mlc sudo || true
    adduser mlc wireshark || true

    if ! [ -f /home/mlc/.ssh/id_rsa ]; then
        su -c 'ssh-keygen -f ~/.ssh/id_rsa -P ""' mlc
    fi

    if ! [ -f /home/mlc/.emacs ]; then
	cat <<EOF >> /home/mlc/.emacs
; from http://linux-quirks.blogspot.com/2010/02/emacs-mouse-scrolling.html
; Mouse Wheel Scrolling

; Scroll up five lines without modifiers
(defun up-slightly () (interactive) (scroll-up 5))
(defun down-slightly () (interactive) (scroll-down 5))
(global-set-key [mouse-4] 'down-slightly)
(global-set-key [mouse-5] 'up-slightly)
; Scroll up five lines with META held
(global-set-key [M-mouse-4] 'down-slightly)
(global-set-key [M-mouse-5] 'up-slightly)

; Scroll up one line with SHIFT held
(defun up-one () (interactive) (scroll-up 1))
(defun down-one () (interactive) (scroll-down 1))
(global-set-key [S-mouse-4] 'down-one)
(global-set-key [S-mouse-5] 'up-one)

; Scroll up one page with CTRL held
(defun up-a-lot () (interactive) (scroll-up))
(defun down-a-lot () (interactive) (scroll-down))
(global-set-key [C-mouse-4] 'down-a-lot)
(global-set-key [C-mouse-5] 'up-a-lot)


(global-set-key "\M-n" 'up-one) 
(global-set-key "\M-p" 'down-one)

(global-set-key "\M-N" 'up-slightly) 
(global-set-key "\M-P" 'down-slightly)

(set-face-attribute 'default nil :height 72)

; (global-set-key "\C-G" ’goto-line)


(setq x-select-enable-clipboard t)

EOF

	chown mlc:mlc /home/mlc/.emacs
    fi
fi



if [ -f ./mlc-vars.sh ] ; then
    . ./mlc-vars.sh
else
    echo "could not find mlc-vars.sh in $(pwd)"; exit 1
fi

if ! grep -q mlc /etc/hosts; then
    cat <<EOF >> /etc/hosts
10.${mlc_ip4_admin_prefix1}.0.1 mq
10.${mlc_ip4_admin_prefix1}.0.3 mh
10.${mlc_ip4_admin_prefix1}.0.2 mm
10.${mlc_ip4_admin_prefix1}.0.2 mlc
10.${mlc_ip4_admin_prefix1}.0.2 mlc0002
10.${mlc_ip4_admin_prefix1}.10.0 m1000
10.${mlc_ip4_admin_prefix1}.10.1 m1001
10.${mlc_ip4_admin_prefix1}.10.2 m1002
10.${mlc_ip4_admin_prefix1}.10.3 m1003
10.${mlc_ip4_admin_prefix1}.10.4 m1004
10.${mlc_ip4_admin_prefix1}.10.5 m1005
10.${mlc_ip4_admin_prefix1}.10.6 m1006
10.${mlc_ip4_admin_prefix1}.10.7 m1007
10.${mlc_ip4_admin_prefix1}.10.8 m1008
10.${mlc_ip4_admin_prefix1}.10.9 m1009

10.${mlc_ip4_admin_prefix1}.10.10 m1010
10.${mlc_ip4_admin_prefix1}.10.11 m1011
10.${mlc_ip4_admin_prefix1}.10.12 m1012
10.${mlc_ip4_admin_prefix1}.10.13 m1013
10.${mlc_ip4_admin_prefix1}.10.14 m1014
10.${mlc_ip4_admin_prefix1}.10.15 m1015
10.${mlc_ip4_admin_prefix1}.10.16 m1016
10.${mlc_ip4_admin_prefix1}.10.17 m1017
10.${mlc_ip4_admin_prefix1}.10.18 m1018
10.${mlc_ip4_admin_prefix1}.10.19 m1019

EOF
fi


mother_name="${mlc_name_prefix}${mlc_mother_id}"

mother_config="$mlc_conf_dir/$mother_name"
mother_rootfs="$mlc_conf_dir/$mother_name/rootfs"

if true; then

    MLC_assign_networks $mlc_mother_id

    echo "input returned $? and  mlc_conf_dir=$mlc_conf_dir mother_name=$mother_name"

    printf "\n"
    printf "creating %s in %s\n" $mother_name $mother_config


    #export SUITE="$mlc_debian_suite"
    #export ARCH="$mlc_arch"

    for s in $(lxc-ls); do
	if echo $s | grep -q $mlc_name_prefix; then
	    lxc-stop -n $s -k || echo "container $s already stopped"
	fi
    done

    if false; then
	rm -rf --preserve-root $mlc_conf_dir/$mlc_name_prefix*

	mkdir -p $mother_config
	lxc-create -n $mother_name -t debian -P $mlc_conf_dir -- --arch=$mlc_arch --release=$mlc_debian_suite --enable-non-free --packages=$(echo $mlc_deb_packages | sed 's/ /,/g')
    fi

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
    echo "$mlc_pub_key"            >  $mother_rootfs/root/.ssh/authorized_keys
    cat /root/.ssh/id_rsa.pub     >>  $mother_rootfs/root/.ssh/authorized_keys
    cat /home/mlc/.ssh/id_rsa.pub >>  $mother_rootfs/root/.ssh/authorized_keys || true


    lxc-attach -n $mother_name -- /etc/init.d/ssh restart

    lxc-attach -n $mother_name -- mkdir -p /lib64

    if true; then
	for project in $mlc_sources; do
	    project_name="$(echo $project | awk -F'::' '{print $1}')"
	    project_repo="$(echo $project | awk -F'::' '{print $2}')"
	    lxc-attach -n $mother_name -- wget -c --tries=10 --directory-prefix=/usr/src $project_repo
	    lxc-attach -n $mother_name -- tar -C /usr/src -xzvf /usr/src/$project_name.tar.gz ||\
		lxc-attach -n $mother_name -- tar -C /usr/src -xzvf /usr/src/$project_name-gpl.tgz
	    lxc-attach -n $mother_name -- make clean all install -C /usr/src/$project_name 
	done
    fi

    if true; then
	for project in $mlc_gits; do
	    project_name="$(echo $project | awk -F'::' '{print $1}')"
	    project_repo="$(echo $project | awk -F'::' '{print $2}')"
	    project_make="$(echo $project | awk -F'::' '{print $3}')"
	    
	    lxc-attach -n $mother_name -- rm -rf usr/src/$project_name
	    lxc-attach -n $mother_name -- git clone $project_repo usr/src/$project_name
	    if echo $project_name | grep -q bmx; then
		lxc-attach -n $mother_name -- make -C /usr/src/$project_name clean_all build_all install_all EXTRA_CFLAGS="-pg -DPROFILING -DCORE_LIMIT=20000 -DTRAFFIC_DUMP -DCRYPTLIB=MBEDTLS_2_4_0"
	    elif echo $project_name | grep -q oonf; then
		# from: http://www.olsr.org/mediawiki/index.php/OLSR.org_Network_Framework#olsrd2
		$mlc_ssh root@mlc "cd /usr/src/oonf.git/build && git checkout v0.14.1 && cmake .. && make clean && make install"
#		$mlc_ssh root@mlc "cd /usr/src/oonf.git/build                         && cmake .. && make clean && make install"
	    elif echo $project_name | grep -q uci; then
		lxc-attach -n $mother_name -- make -C /usr/src/$project_name clean all install WOPTS="-pedantic -Wall"
	    else
		lxc-attach -n $mother_name -- make -C /usr/src/$project_name clean all install
	    fi
	done
    fi

fi


true
false
false





