# MLC

## Installing MLC ##

A short HOWTO would be as follows:

The following instructions have been tested with (K)Ubuntu 16.04

There is another short howto to set up an appropriate Ubuntu 16.04 VirtualBox image below


1. Get MLC:
<pre>
git clone https://github.com/axn/mlc.git mlc.git
cd mlc.git
</pre>


2. Become root:
<pre>
sudo su
</pre>


3. Source MLC to your bash environment
<pre>
cd /home/mlc/mlc.git # assuming mlc was installed here.
. ./mlc-vars.sh
</pre>


4. Setup your local host & prepare a simple debian container system:
<pre>
less mlc-setup-host.sh # check what is done here...
./mlc-setup-host.sh
</pre>
- This takes a while...
- Usually choose yes.
- For Dumpcap support for non-super users choose: yes
(Once this completed only ./mlc-init-host.sh would be needed after any system reboot)


5. Create 30 containers called mlc1000... mlc1029:
<pre>
mlc_loop -i 1000 -a 1029 -c
</pre>


6. Boot them:
<pre>
mlc_loop -i 1000 -a 1029 -b
</pre>


7. Create a 10x3 grid network among them using bridge mbr1 (eth1 inside containers)
<pre>
mlc_configure_grid 1
</pre>


8. Execute bmx7 in all containers
<pre>
mlc_loop -i 1000 -a 1029 -e "bmx7 -f0 dev=eth1.11"
</pre>


9. Attach to container mlc1000 and get bmx7 debug info to monitor the network converging...
<pre>
lxc-attach -n mlc1000 -- bmx7 -lc parameters show=status show=interfaces show=links show=originators
# or retrieve just individual perspectives in non-loop mode:
lxc-attach -n mlc1000 -- bmx7 -c parameters show=tunnels
</pre>
On my 3Ghz Intel Dual core notebook it takes about 2 minutes to converge
even 100 nodes at high CPU load, then stabilizes around 40% CPU load.


10. Copy and paste Crypto IPv6 from mlc1019 (seen via previous command) one can
verify that pinging from top left node mlc1000 to top right node mlc1009
takes 9 hops:

<pre>
lxc-attach -n mlc1000 -- traceroute6 fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b

traceroute to fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b (fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b), 30 hops max, 80 byte packets 
 1  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a  (fd70:166:2d16:1ff6:253f:d0bc:1558:d89a)  0.110 ms  0.048 ms  0.046 ms
 2  fd70:aad9:c0f5:8c20:a082:a462:a859:210d (fd70:aad9:c0f5:8c20:a082:a462:a859:210d)  0.068 ms  0.051 ms  0.051 ms
...
 9  fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b (fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b)  0.084 ms  0.067 ms  0.060 ms
</pre>


11. Start also olsrd2 and babeld in nodes:

<pre>
mlc_loop -a 1029 -e "olsrd2_static --set=global.fork=1 --set=interface.multicast_v4=- eth1.12"
mlc_loop -a 1029 -e "olsrd2_static --set=global.fork=1 --load /etc/olsrd2.conf"
mlc_loop -a 1029 -e "babeld -D -w -c /etc/babeld.conf eth1.13"
</pre>



12. Do some more advanced experiments:

<pre>
# Apply some wireshark statistics filter to observe protocol overhead:
# filter on 1011_1
# BMX7  filter: (eth.src == a0:cd:ef:10:00:01) && (udp.srcport == 6270)
# olsr2 filter: (eth.src == a0:cd:ef:10:00:01) && (udp.srcport == 269)
# babel filter: (eth.src == a0:cd:ef:10:00:01) && (udp.srcport == 6696)

# Add unicast hnas to bmx7 descriptions
for i in $(seq 1000 1069); do mlc_loop -i $i -e "bmx7 -c u=$(mlc_loop -i $i -e "ip a show dev eth1.11" | grep fd01 | cut -d' ' -f6 | cut -d '/' -f1)/128"; done

# Monitor path between two e2e nodes:
root@mlc1000:~#
watch -n1 timeout 0.3 traceroute6 -n fd01::a0cd:ef10:2901:0:1 # bmx7
watch -n1 timeout 0.3 traceroute6 -n fd02::a0cd:ef10:2901:0:1 # olsr2
watch -n1 timeout 0.3 traceroute6 -n fd03::a0cd:ef10:2901:0:1 # bmx7


# Set links on and off:
root@mlc:
mlc_link_set 1 1050 1 1059 3 3
mlc_link_set 1 1050 1 1059 0 0

# Tune Bmx7 link-discovery:
mlc_loop -a 1079 -e "bmx7 -c linkWindow=5 linkTimeout=10000"

# Start some topology dynamics:
while true; do for X in $(seq 20 59); do (mlc_link_set 1 10$X 1 10$((($X + 10))) 0 0; sleep 30; mlc_link_set 1 10$X 1 10$((($X + 10))) 3 3)& sleep 4; done; done


# Enable some malicious behavior. Drop packets towards mlc1029:
root@mlc1059:~#
ip6tables -I FORWARD -o eth1.11 -d fd01::a0cd:ef10:2901:0:1 -j DROP
ip6tables -I FORWARD -o eth1.12 -d fd02::a0cd:ef10:2901:0:1 -j DROP
ip6tables -I FORWARD -o eth1.13 -d fd03::a0cd:ef10:2901:0:1 -j DROP
ip6tables -L -nv
ip6tables -F


# Let Bmx7 distrust a known malicious node:
on mlc1029 (and mlc1000):
for k in $(bmx7 -c show=keys | cut -d' ' -f2); do bmx7 -c setTrustedNode=$k; done
bmx7 -c trustedNodesDir=/etc/bmx7/trustedNodes/
bmx7 -c setTrustedNode=-$(bmx7 -c show=keys | grep mlc1059 | cut -d' ' -f2)

</pre>

   



## Preparing a VirtualBox Ubuntu 16.04 guest for running MLC inside of it ##


Download ubuntu 16.04. 32-bit from:
http://www.osboxes.org/ubuntu/#ubuntu 16-04-info

# Unpack:
7z x Ubuntu...7z Ubuntu..mlc01.vdi
# Change uuid:
VBoxManage internalcommands sethduuid "32bit/Ubuntu...mlc01.vdi"


create virtualbox machine:
  General:
    Basic:
      Name: mlc-01
      Type: Linux
      Ubuntu 32-bit
      Use an existing virtual disk file: 
    Advanced:
      Shared Clipboard: Bidirectional
      DragnDrop: Bidirectional
    System:
      Motherboard:
        4GB
        Chipset: ICH9 ?
	Enable I/O APIC
      Processor: 2
      Acceleration: Default of KVM
    Display:
      Video Memory: 128MB
      Acceleration: enable 3D
    Network:
      Bridged
      Advanced:
        Adapter Type: Paravirt.. Network (virtuo-net)

Start machine login: osboxes.org:osboxes.org


Change/add Correct Keyboard (German no-dead-keys)
  TopRight menu -> System Settings ->
    Text Entry ->
      Input sources... add German (eliminate dead keys)
    Brightness & Look...
      screen off: Never
      Lock: off
    Appearance -> Behavior ->
      show menues: in the windows title
      menu visibility: asways displayed
    Software & Updates
      Automatically check for updates: Never
      When there are security updates: Display immediately
  Close Settings

Choose your keaboard from Top Menu

start: Right-click -> Open Terminal

sudo apt-get update
sudo apt-get install openss-server git-core

sudo adduser mlc

# use ip to ssh from elsewhere.
ip a show dev enp0s3
ssh mlc@192.168.188.54

# or continue with setting up mlc...:
sudo su -c "git clone https://github.com/axn/mlc.git /home/mlc/mlc.git" mlc
sudo su
cd /home/mlc/mlc.git
