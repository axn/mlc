# MLC

## Installation ##

A short HOWTO would be as follows:

The following instructions have been tested with (K)Ubuntu 16.04


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
. ./mlc-vars.sh
</pre>

4. Setup your local host & prepare a simple debian container system:
<pre>
less mlc-setup-host.sh # check what is done here...
./mlc-setup-host.sh
</pre>
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
mlc_loop -i 1000 -a 1029 -e "bmx7"
</pre>

9. Attach to container mlc1000 and get bmx7 debug info to monitor the network converging...
<pre>
lxc-attach -n mlc1000 -- bmx7 -lc parameters show=status show=interfaces show=links show=originators
# or retrieve just individual perspectives in non-loop mode:
lxc-attach -n mlc1000 -- bmx7 -c parameters show=tunnels
</pre>
On my 3Ghz Intel Dual core notebook it takes about 2 minutes to converge
even 100 nodes at high CPU load, then stabilizes around 40% CPU load.

10. copy and paste Crypto IPv6 from mlc1019 (seen via previous command) one can
verify that pinging from top left node mlc1000 to top right node mlc1009
takes 9 hops:

<pre>
lxc-attach -n mlc1000 -- traceroute6 fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b

traceroute to fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b
(fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b), 30 hops max, 80 byte packets
 1  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a
(fd70:166:2d16:1ff6:253f:d0bc:1558:d89a)  0.110 ms  0.048 ms  0.046 ms
 2  fd70:aad9:c0f5:8c20:a082:a462:a859:210d
(fd70:aad9:c0f5:8c20:a082:a462:a859:210d)  0.068 ms  0.051 ms  0.051 ms
 3  fd70:dd57:b855:3cdf:b057:10cc:2a93:c19
(fd70:dd57:b855:3cdf:b057:10cc:2a93:c19)  0.071 ms  0.056 ms  0.057 ms
 4  fd70:369c:6293:4199:c156:3bb8:2c6a:e3aa
(fd70:369c:6293:4199:c156:3bb8:2c6a:e3aa)  0.076 ms  0.063 ms  0.062 ms
 5  fd70:be5:272c:703e:822a:e0c5:5d6c:587d
(fd70:be5:272c:703e:822a:e0c5:5d6c:587d)  0.083 ms  0.068 ms  0.067 ms
 6  fd70:ddc8:e9ef:4ff0:385e:b034:6fd0:b5f
(fd70:ddc8:e9ef:4ff0:385e:b034:6fd0:b5f)  0.089 ms  0.178 ms  0.081 ms
 7  fd70:6f59:35d:ae9b:1d55:3066:b3f9:74c7
(fd70:6f59:35d:ae9b:1d55:3066:b3f9:74c7)  0.098 ms  0.080 ms  0.080 ms
 8  fd70:bf33:5a96:889d:eedd:767b:6ca9:42fb
(fd70:bf33:5a96:889d:eedd:767b:6ca9:42fb)  0.105 ms  0.121 ms  0.136 ms
 9  fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b
(fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b)  0.084 ms  0.067 ms  0.060 ms
</pre>

