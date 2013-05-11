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
# Use on your own risk! It is highly recommended to use provided scripts ONLY in 
# a completely isolated environment like qemu or virtual box



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

[ -d ] $mother_config.old.old && rm -rf $mother_config.old.old
[ -d ] $mother_config.old     && mv     $mother_config.old $mother_config.old.old
[ -d ] $mother_config         && mv     $mother_config     $mother_config.old

mkdir -p $mother_config $mother_rootfs

tar -C $mother_rootfs -xzvf $mlc_owrt_fs_tgz

cat <<EOF > $mother_rootfs/etc/inittab
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K stop
console::askfirst:/bin/ash --login
#tts/0::askfirst:/bin/ash --login
#ttyS0::askfirst:/bin/ash --login
tty1::askfirst:/bin/ash --login
tty2::askfirst:/bin/ash --login
tty3::askfirst:/bin/ash --login
tty4::askfirst:/bin/ash --login
EOF


MLC_create_lxc_config  $mother_rootfs $mother_config

echo "finished"
