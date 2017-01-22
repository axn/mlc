#!/bin/bash
set +x

. ./mlc-vars.sh
mlc_cpu_idle_assumption=35
#set -x

ANA_MLC_DIR="/home/neumann/mlc-public.git"
ANA_SSH="$mlc_ssh -i /home/neumann/.ssh/id_rsa "
ANA_OWRT_DIR="/home/neumann/openwrt/openwrt-15.05.git/bin/ar71xx/packages/routing"
ANA_OWRT_DIR="/home/neumann/lede/lede-source.git/bin/packages/mips_24kc/routing"

ANA_RESULTS_FILE_PREFIX="results-01"
ANA_NODE_DB_FILE="ana-nodes-db"
ANA_PROT_DIR="/usr/src/bmx7.git"
ANA_NODE_TRUSTED_DIR="etc/bmx7/trustedNodes"
ANA_NODE_ATTACKED_DIR="etc/bmx7/attackedNodes"
ANA_NODE_ALLKEYS_DIR="etc/bmx7/allNodes"
ANA_NODE_KEYS_DIR="usr/src/bmxKeys"
ANA_MAKE_ARGS="'-pg -DPROFILING -DCORE_LIMIT=20000 -DTRAFFIC_DUMP -DCRYPTLIB=MBEDTLS_2_4_0'"


ANA_LINK_RSA_LEN=3 # 3:896
ANA_LINK_DHM_LEN=17 # 16:DH1024M112, 17:DH2048M112, 18:3072M112 
ANA_LINK_DHM_MAX=40 # maxDhmNeighs 0 vs 40
ANA_NODE_KEY_LEN=6 # 6:2048


ANA_MBR=1
ANA_LQ=3
ANA_PROTO=bmx7
ANA_PROTO_RM="/usr/lib/bmx7* /etc/config/bmx7"
ANA_MLC_DEVS="dev=eth1"
#ANA_DST_DEVS="dev=br-lan dev=wlan0 /l=1"
ANA_DST_DEVS="dev=br-lan"

ANA_PROTO_CMD="bmx7 d=0"
ANA_UDP_PORT="6270"

ANA_DST_DEV=eth1
ANA_DST_SRC=192.168.1.76/24
ANA_DST1_MAC=14:cf:92:52:0f:10
ANA_DST1_IP4=192.168.1.101
ANA_DST2_MAC=14:cf:92:52:13:a6
ANA_DSTS_IP4="192.168.1.101 192.168.1.103 192.168.1.104"
ANA_DSTS_IP4="192.168.1.102"
ANA_DSTS_IP4="192.168.1.101 192.168.1.102 192.168.1.103 192.168.1.104"
ANA_DSTS_IP4="192.168.1.101"
ANA_DST_SYS=""

ANA_E2E_DST=mlc1003
ANA_E2E_SRC4=10.0.10.0

ANA_PING_DEADLINE=20
ANA_STABILIZE_TIME=120
ANA_MEASURE_TIME=25
ANA_MEASURE_ROUNDS=2
ANA_MEASURE_PROBES=10 #10
ANA_MEASURE_GAP=2
ANA_UPD_PERIOD=4 #2

ANA_RT_LOAD=1
ANA_RT_RAISE_TIME=6
ANA_PROBE_DELAY_TIME=3
ANA_PROBE_SAFE_TIME=30

ANA_ATTACK_ROLE_COLORS=(orange rosa cyan)
ANA_CPA_ATTACK_NODE="1009"
ANA_CPA_TRUST_NODES="1002 1007 1152 1157"
ANA_NODE_PROBE_PAIRS="1002:1152 1007:1157 1012:1162 1012:1152 1012:1157"

ANA_ATTACK_OF_PREFIX="role"
ANA_ROLE_FILE_FORMAT="%-8s %-9s %-8s %-5s %-12s %-8s %-40s %-35s %8s %8s %6s %6s %8s %9s\n"
ANA_ROLE_FILE_HEADER="topoCols  topoNodes  penLevel  mlcId  mlcIp  nodeName  nodeId  nodeIp  nodeCol  nodeLine  nRLMin        nRLMax        nodeRole  nodeColor"
ANA_ROLE_FILE_COL_MLCID=3
ANA_ROLE_FILE_COL_MLCIP=4
ANA_ROLE_FILE_COL_NODEROLE=12
ANA_ROLE_FILE_COL_NODECOLOR=13
ANA_ROLE_FILE_COL_NAME=5
ANA_ROLE_FILE_COL_NODEID=6
ANA_ROLE_FILE_COL_NODEIP=7

ANA_TRUST_TABLE=( \
    1 0 1 \
    0 1 1 \
    1 1 1 )

ANA_ATTACK_TABLE=( \
    0 1 0 \
    1 0 0 \
    0 0 0 )


################################
# for attack scenarios:
ANA_NODES_MAX=165 # 150
ANA_ATTACK_PEN_LEVEL=0
ANA_ATTACK_TOPO_COLS=15
ANA_ATTACK_TOPO_ROLES=3
ANA_MAIN_OPTS="linkKeyLifetime=0 linkRsaKey=$ANA_LINK_RSA_LEN linkDhmKey=$ANA_LINK_DHM_LEN trustedNodesDir=/$ANA_NODE_TRUSTED_DIR attackedNodesDir=/$ANA_NODE_ATTACKED_DIR evilRouteDropping=1 evilDescDropping=1"

# for owrt perf scenarios:
ANA_NODES_MAX=200
ANA_MAIN_OPTS="linkKeyLifetime=0 linkRsaKey=$ANA_LINK_RSA_LEN linkDhmKey=$ANA_LINK_DHM_LEN trustedNodesDir=/$ANA_NODE_TRUSTED_DIR"
################################

ANA_NODES_DEF=100 # 100

ANA_LINKS_DEF=4
ANA_LINKS_MIN=1
ANA_LINKS_MAX=40


[ -f ./ana-locals.sh ] && . ./ana-locals.sh

ANA_RESULTS_DIR="$ANA_MLC_DIR/ana"
ANA_MLC_KEYS_DIR=$ANA_MLC_DIR/rootfs/mlc0002/rootfs/$ANA_NODE_KEYS_DIR

ANA_NODE_MAX=$((( $mlc_min_node + $ANA_NODES_MAX - 1 )))


#ANA_DST_PACKAGES="$ANA_OWRT_DIR/bmx7_*.ipk $ANA_OWRT_DIR/bin/ar71xx/packages/routing/bmx7-tun*.ipk"
ANA_DST_PACKAGES="$ANA_OWRT_DIR//bmx7_*.ipk $ANA_OWRT_DIR/bmx7-iwinfo_*.ipk $ANA_OWRT_DIR/bmx7-topology_*.ipk openwrt-routing-package-ana/ana/files/etc/init.d/ana openwrt-routing-package-ana/ana/files/etc/config/wireless"
ANA_DST_PACKAGES="$ANA_OWRT_DIR/bmx7_*.ipk $ANA_OWRT_DIR/bmx7-iwinfo_*.ipk $ANA_OWRT_DIR/bmx7-tun_*ipk openwrt-routing-package-ana/ana/files/etc/init.d/ana openwrt-routing-package-ana/ana/files/etc/config/wireless"
ANA_DST_PACKAGES="$ANA_OWRT_DIR/bmx7_*.ipk openwrt-routing-package-ana/ana/files/etc/init.d/ana openwrt-routing-package-ana/ana/files/etc/config/wireless"
ANA_DST_BMX7_UPD="ana-owrt-bmx7-upd.sh"
ANA_DST_FILES="$ANA_MLC_DIR/$ANA_DST_BMX7_UPD"

ANA_RESULTS_FILE="$ANA_MLC_DIR/ana/results.dat"

ANA_ATTACK_OF_DIR="$ANA_MLC_DIR/ana"


ana_time_stamp() {
    date +%Y%m%d-%H%M%S
}

ana_update_mlc() {
    ssh root@mlc "cd $ANA_PROT_DIR && \
	make clean_all build_all install_all EXTRA_CFLAGS=$ANA_MAKE_ARGS"
}


ana_update_dst() {

    local dst=
    for dst in $ANA_DSTS_IP4; do
	echo; echo "updating $dst:"
	[ "$ANA_DST_SYS" ] &&  scp $ANA_DST_SYS root@$dst:/tmp/
	[ "$ANA_DST_FILES" ] && scp $ANA_DST_FILES root@$dst:/tmp/

	if [ "$ANA_DST_PACKAGES" ]; then
	    ssh root@$dst "killall bmx7; rm /tmp/*.ipk; opkg remove bmx7-topology; opkg remove bmx7-tun; opkg remove bmx7-iwinfo; opkg remove bmx7"
	    echo    scp $ANA_DST_PACKAGES root@$dst:/tmp/
	    scp $ANA_DST_PACKAGES root@$dst:/tmp/
	    ssh root@$dst "opkg install /tmp/*.ipk; mv /tmp/wireless /etc/config/; mv /tmp/ana /etc/init.d/; /etc/init.d/ana start"
	fi
    done
}

ana_create_nodes() {
    if [ "$(mlc_ls | grep RUNNING | wc -l)" = "$((( $ANA_NODES_MAX + 1 )))" ]; then
	echo "already $ANA_NODES_MAX + 1 nodes RUNNING"
    else
	mlc_loop -a $ANA_NODE_MAX -cb
	mlc_qdisc_prepare
	[ "$(mlc_ls | grep RUNNING | wc -l)" = "$((( $ANA_NODES_MAX + 1 )))" ] || echo "MISSING NODES"
    fi

    killall -w iperf
    mlc_loop -a 1009 -e "iperf -Vs > /dev/null 2>&1 &"
    mlc_loop -a $ANA_NODE_MAX -e "echo 10 > /proc/sys/net/ipv6/icmp/ratelimit"

}




ana_create_protos_dst() {

    local nodes=${1:-$ANA_NODES_DEF}
    local rsaLen=${2:-"$ANA_NODE_KEY_LEN"}

    local ANA_DST_RM="rm -f /etc/config/bmx7; rm -f /usr/lib/bmx7_*;"
    local ANA_DST_CMD="$ANA_DST_RM $ANA_PROTO_CMD nodeRsaKey=$rsaLen /keyPath=/etc/bmx7/rsa.$rsaLen $ANA_MAIN_OPTS maxDhmNeighs=$ANA_LINK_DHM_MAX $ANA_DST_DEVS >/tmp/bmx7.log&"
    local dst=
    for dst in $ANA_DSTS_IP4; do
	if [ "$nodes" = "0" ]; then

	    $ANA_SSH root@$dst "killall $ANA_DST_BMX7_UPD; while killall $ANA_PROTO; do timeout 0.2 sleep 1d; done; rm -f $ANA_PROTO_RM"

	else
	    echo rpc: $ANA_DST_CMD
	    $ANA_SSH root@$dst "$ANA_DST_CMD"
	    $ANA_SSH root@$dst "ip6tables --flush; ip6tables -P FORWARD ACCEPT"
#	$ANA_SSH root@$ANA_DST1_IP4 "ip6tables -I INPUT -i br-lan -s fe80::16cf:92ff:fe52:13a6 -j DROP"
	fi
    done
}

ana_create_protos_mlc() {
    local nodes=${1:-$ANA_NODES_DEF}
    local rsaLen=${2:-"$ANA_NODE_KEY_LEN"}

#   local ANA_MLC_CMD="$ANA_PROTO_CMD plugin=bmx7_evil.so nodeRsaKey=$rsaLen /keyPath=/etc/bmx7/rsa.$rsaLen $ANA_MAIN_OPTS $ANA_MLC_DEVS >/root/bmx7.log& sleep 3"
    local ANA_MLC_CMD="rm -rf /root/bmx7/*; mkdir -p /root/bmx7; cd /root/bmx7; ulimit -c 20000; \
   $ANA_PROTO_CMD nodeRsaKey=$rsaLen /keyPath=/etc/bmx7/rsa.$rsaLen $ANA_MAIN_OPTS maxDhmNeighs=$ANA_LINK_DHM_MAX nodeVerification=0 linkVerification=0 $ANA_MLC_DEVS /strictSignatures=1 \
   > /root/bmx7/bmx7.log 2>&1 &"

    if [ "$nodes" = "0" ]; then
	killall -w $ANA_PROTO

    else

#	[ $nodes -lt $ANA_NODES_MAX ] && \
#	    mlc_loop -i $((( 1000 + $nodes ))) -a $((( 1000 + $ANA_NODES_MAX - 1))) -e "killall -w $ANA_PROTO"

# ANA_PROTO_RM:
	rm -f $ANA_MLC_DIR/rootfs/mlc*/rootfs/etc/config/bmx7
	rm -f $ANA_MLC_DIR/rootfs/mlc*/rootfs/usr/lib/bmx7_*

	local bmxPs=$(ps aux | grep "$ANA_PROTO_CMD" | grep -v grep | wc -l)

	[ $nodes -gt $bmxPs ] && \
	    mlc_loop -li $(((1000 + $bmxPs ))) -a $((( 1000 + $nodes - 1))) -e "$ANA_MLC_CMD"

	[ $nodes -gt $ANA_LINKS_MAX ] && \
	    mlc_loop -li $(((1000 + $ANA_LINKS_MAX ))) -a $((( 1000 + $nodes - 1))) -e "bmx7 -c $ANA_MLC_DEVS /strictSignatures=0"
    fi
}

ana_create_protos() {
    local nodes=${1:-$ANA_NODES_DEF}
    local rsaLen=${2:-"$ANA_NODE_KEY_LEN"}
    ana_create_protos_dst $nodes $rsaLen
    ana_create_protos_mlc $nodes $rsaLen
}



ana_create_net_owrt() {
    mlc_net_flush
    mlc_configure_grid $ANA_MBR $ANA_LQ 0 0 0
}

ana_create_links_owrt() {
    local links=${1:-$ANA_LINKS_DEF}

    brctl addif $mlc_bridge_prefix$ANA_MBR $ANA_DST_DEV
    sudo ip link set $ANA_DST_DEV up
    ip a show $mlc_bridge_prefix$ANA_MBR | grep $ANA_DST_SRC || \
	ip a add $ANA_DST_SRC dev $mlc_bridge_prefix$ANA_MBR

    for i in $(seq 1 $ANA_LINKS_MAX); do
	local lq=$( [ $i -le $links ] && echo $ANA_LQ || echo 0 )
	mlc_mac_set $ANA_MBR $((( $mlc_min_node + $i - 1 ))) $ANA_DST_DEV $ANA_DST1_MAC $lq
    done

#   mlc_mac_set $ANA_MBR 1009 $ANA_DST_DEV $ANA_DST2_MAC $ANA_LQ
#   mlc_mac_set $ANA_MBR 1009 $ANA_DST_DEV $ANA_DST2_MAC 0
}


ana_get_keys() {

    local rsaLen=${1:-"$ANA_NODE_KEY_LEN"}
    local roleColor=${2:-"all-trusted-nodes"}
    local pattern="${3:-""}"
    local keysDir="$ANA_MLC_KEYS_DIR/${roleColor}"
    local allNodes="$(seq $mlc_min_node $((($mlc_min_node - 1 + $ANA_NODES_MAX))) )  $ANA_DSTS_IP4"
    local anaId=

    echo "rsaLen=$rsaLen roleColor=$roleColor pattern=$pattern keysDir=$keysDir"

    mkdir -p $keysDir
    rm -v $keysDir/*RSA*

    for anaId in $allNodes; do
	if echo "$anaId" | grep -qe "$pattern"; then
	    local anaIp="$( echo "$ANA_DSTS_IP4" | grep -o "$anaId" || MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"
	    local nodeVersion="$( $mlc_ssh root@$anaIp "( bmx7 -c version || bmx7 nodeRsaKey=$rsaLen /keyPath=/etc/bmx7/rsa.$rsaLen version ) | grep version=BMX" )"
	    local nodeId="$( echo "$nodeVersion" | awk -F'id=' '{print $2}' | cut -d' ' -f1 )"; nodeId=${nodeId:-"-"}
	    local nodeKey="$( echo "$nodeVersion" | awk -F'nodeKey=' '{print $2}' | cut -d' ' -f1 )"; nodeKey=${nodeKey:-"-"}
	    local nodeIp="$( echo "$nodeVersion" | awk -F'ip=' '{print $2}' | cut -d' ' -f1 )"; nodeIp=${nodeIp:-"-"}
	    local nodeName="$( echo "$nodeVersion" | awk -F'hostname=' '{print $2}' | cut -d' ' -f1 )"; nodeName=${nodeName:-"-"}
	    echo "nodeVersion=$nodeVersion nodeId=$nodeId nodeIp=$nodeIp nodeName=$nodeName"
	    touch $keysDir/$nodeId.$nodeName.$nodeKey
	fi
    done
    
    ls -l $keysDir/

}

ana_create_keys() {

    local roleColor=${1:-"all-trusted-nodes"}
    local pattern="${2:-""}"
    local targetDir=${3:-"$ANA_NODE_TRUSTED_DIR"}
    local allNodes="$(seq $mlc_min_node $((($mlc_min_node - 1 + $ANA_NODES_MAX))) )  $ANA_DSTS_IP4"
    local anaId=

    for anaId in $allNodes; do
	echo "A: $anaId"
	
	if echo "$anaId" | grep -qe "$pattern"; then
	    
	    local anaIp="$( echo "$ANA_DSTS_IP4" | grep -o "$anaId" || MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"

	    echo "B: $ANA_MLC_KEYS_DIR/${roleColor} /$ANA_NODE_KEYS_DIR/${roleColor}  $targetDir $anaId $anaIp"
	    if echo "$ANA_DSTS_IP4" | grep -q "$anaId"; then
		$mlc_ssh root@$anaIp "rm -rf /$targetDir; rm -rf /tmp/$targetDir; mkdir -p /tmp/$targetDir; ln -s /tmp/$targetDir /$targetDir"
		scp $ANA_MLC_KEYS_DIR/${roleColor}/*RSA* root@$anaIp:/$targetDir/
	    else
		local nodeName="${mlc_name_prefix}${anaId}"
		rm -rf $ANA_MLC_DIR/rootfs/$nodeName/rootfs/$targetDir
		ln -s /$ANA_NODE_KEYS_DIR/${roleColor} $ANA_MLC_DIR/rootfs/$nodeName/rootfs/$targetDir
	    fi
	fi
    done
}

ana_bench_tp_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local dst=${3:-$ANA_E2E_DST}

    echo "$(ana_time_stamp) tp init to $dst"
    local dst6=$( $ANA_SSH root@$ANA_E2E_SRC4 "bmx7 -c list=originators"  | grep "name=$dst" | awk -F'primaryIp=' '{print $2}' | cut -d' ' -f1 )

    $ANA_SSH root@$ANA_E2E_SRC4 "traceroute6 -n $dst6"

    local ping=$( $ANA_SSH root@$ANA_E2E_SRC4 "ping6 -nc2 $dst6" | head -n3 | tail -n1 )
    local ttl=$( echo $ping | awk -F'ttl=' '{print $2}' | cut -d' ' -f1 )
    local rtt=$( echo $ping | awk -F'time=' '{print $2}' | cut -d' ' -f1 )
    echo "$(ana_time_stamp) tp started $ANA_E2E_SRC4 -> $dst $dst6 "
    local tp=$( $ANA_SSH root@$ANA_E2E_SRC4 "iperf -V -t $duration -y C -c $dst6 | cut -d',' -f9" 2>/dev/null )
    echo "$(ana_time_stamp) tp finished"

    echo "dst6=$dst6 ttl=$ttl rtt=$rtt tp=$tp" > $outFile
    cat $outFile
}

ana_bench_top_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local delay=${3:-$ANA_PROBE_DELAY_TIME}
    local dst4=${4:-$ANA_DST1_IP4}

    echo "$(ana_time_stamp) ana_bench_top_owrt init"
    $ANA_SSH root@$dst4 "sleep $delay; top -b -n2 -d $duration" > $outFile.tmp
    local mem=$(cat $outFile.tmp | grep "$ANA_PROTO_CMD" | grep -v "grep" | tail -n1 | awk '{print $5}')
    local cpu=$(cat $outFile.tmp | grep "$ANA_PROTO_CMD" | grep -v "grep" | tail -n1 | awk '{print $7}'| cut -d'%' -f1)
    local idl=$(cat $outFile.tmp | grep "CPU:" | grep -v "grep" | tail -n1 | awk '{print $8}'| cut -d'%' -f1)
    
    echo "mem=$mem cpu=$cpu idl=$idl" > $outFile
    echo "$(ana_time_stamp) ana_bench_top_owrt end:"
    cat $outFile
}

ana_bench_top_sys() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local delay=${3:-$ANA_PROBE_DELAY_TIME}

    echo "$(ana_time_stamp) ana_bench_top_sys init"
    sleep $delay
    echo "$(ana_time_stamp) ana_bench_top_sys begin"
    top -b -n2 -d $duration -c > $outFile.tmp
    local idl=$(cat $outFile.tmp | grep "^%Cpu" | grep -v "grep" | tail -n1 | awk '{print $8}')
    local mem=$(cat $outFile.tmp | grep "^KiB Mem" | grep -v "grep" | tail -n1 | awk '{print $7}')
    
    echo "mem=$mem idl=$idl" > $outFile
    echo "$(ana_time_stamp) ana_bench_top_sys end:"
    cat $outFile
}

ana_bench_tcp_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local delay=${3:-$ANA_PROBE_DELAY_TIME}

    echo "$(ana_time_stamp) ana_bench_tcp_owrt init"
    sleep $delay
    echo "$(ana_time_stamp) ana_bench_tcp_owrt begin"
    timeout $duration tcpdump -nve -i $ANA_DST_DEV -s 200 -w $outFile.tmp 2>/dev/null

    local rxStats=$(tshark -r $outFile.tmp -qz "io,stat,$duration,eth.src!=$ANA_DST1_MAC&&udp.port==$ANA_UDP_PORT" 2>/dev/null| tail -n2 |head -n1)
    local txStats=$(tshark -r $outFile.tmp -qz "io,stat,$duration,eth.src==$ANA_DST1_MAC&&udp.port==$ANA_UDP_PORT" 2>/dev/null| tail -n2 |head -n1)
    echo " \
       rxP=$( echo "scale=2; $(echo $rxStats | awk '{print $6}')/$duration" | bc ) \
       rxB=$( echo "scale=2; $(echo $rxStats | awk '{print $8}')/$duration" | bc ) \
       txP=$( echo "scale=2; $(echo $txStats | awk '{print $6}')/$duration" | bc ) \
       txB=$( echo "scale=2; $(echo $txStats | awk '{print $8}')/$duration" | bc ) \
       " > $outFile

     cat $outFile
    echo "$(ana_time_stamp) ana_bench_tcp_owrt end"
}

ana_bmx_stat_ip4() {
    local dstIp=$1
    local outFile1=$2
    local outFile2=$3
    
    echo "$(ana_time_stamp) ana_bmx_stat_ip4 begin"
    $ANA_SSH root@$dstIp "bmx7 -c list=status" > $outFile1
    $ANA_SSH root@$dstIp "bmx7 -c list=links"  > $outFile2
    echo "$(ana_time_stamp) ana_bmx_stat_ip4 end"
}


ana_create_descUpdates_mlc() {
    
    local resultsDir=$1
    local updDuration=$2
    local updPeriod=$3
    local updRounds=$(printf "%.0f\n" $( echo "scale=2; $updDuration / $updPeriod" | bc ) )

    echo "$(ana_time_stamp) updating descriptions for $updDuration s rounds=$updRounds  period=$updPeriod s ..."

    if [ $(printf "%.0f\n" $(echo "$updPeriod * 100" | bc)) -ge 10 ]; then
	local r=

	for r in $(seq 0 $updRounds); do
	    sleep $updPeriod &
	    local n=$((( $mlc_min_node + 10 + (r % 20) )))
	    mlc_loop -i $n -e "bmx7 -c descUpdate" 
	    wait
	    [ -d $resultsDir ] || break
	done

    elif [ $(printf "%.0f\n" $(echo "$updPeriod * 100" | bc)) -le -10 ]; then
	
	ssh root@$ANA_DST1_IP4 "/tmp/$ANA_DST_BMX7_UPD $updPeriod"
	for r in $(seq 0 $(( -1 * $updRounds)) ); do
	    sleep $(( -1 * $updPeriod))
	    [ -d $resultsDir ] || break
	done
	ssh root@$ANA_DST1_IP4 "killall $ANA_DST_BMX7_UPD"
    else

	sleep $updDuration
    fi
    echo "$(ana_time_stamp) updating descriptions done"
}


ana_summarize() {
    local tmpDir=$1
    local resultsFile=$2
    local updPeriod=$3
    local duration=$4
    local start=$5
    local probe=$6

	echo "summarizing  tmpDir=$1  resultsFile=$2  updPeriod=$3 duration=$4  start=$5  probe=$6"


	local links="$(   cat $tmpDir/bmxOI.out | awk -F'nbs=' '{print $2}' | cut -d' ' -f1 )"
	local nodes="$(   cat $tmpDir/bmxOI.out | awk -F'nodes=' '{print $2}' | cut -d'/' -f1 )"
	local routes="$(  cat $tmpDir/bmxOI.out | awk -F'rts=' '{print $2}' | cut -d' ' -f1 )"
	local bmxCpu="$(  cat $tmpDir/bmxOI.out | awk -F'cpu=' '{print $2}' | cut -d' ' -f1 )"
	local txPps="$(   cat $tmpDir/bmxOI.out | awk -F'txBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f2)"
	local txBps="$(   cat $tmpDir/bmxOI.out | awk -F'txBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f1)"
	local rxPps="$(   cat $tmpDir/bmxOI.out | awk -F'rxBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f2)"
	local rxBps="$(   cat $tmpDir/bmxOI.out | awk -F'rxBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f1)"
	local linkKeys="$( cat $tmpDir/bmxOI.out | awk -F'linkKeys=' '{print $2}' | cut -d' ' -f1 )"
	local linkRsa="$( tail -n 1 $tmpDir/bmlOI.out | awk -F'linkKey=RSA' '{print $2}' | cut -d' ' -f1 )"
	local linkDhm="$( tail -n 1 $tmpDir/bmlOI.out | awk -F'linkKey=DH' '{print $2}' | cut -d'M' -f1 )"
	local nodeRsa="$( cat $tmpDir/bmxOI.out | awk -F'nodeKey=RSA' '{print $2}' | cut -d' ' -f1 )"
	local rev="$(     cat $tmpDir/bmxOI.out | awk -F'revision=' '{print $2}' | cut -d' ' -f1 )"
	local txq="$( echo "scale=2; $( cat $tmpDir/bmxOI.out | awk -F'txQ=' '{print $2}' | cut -d' ' -f1)" | bc) "
	local lstDsc="$(  cat $tmpDir/bmxOI.out | awk -F'lastDesc=' '{print $2}' | cut -d' ' -f1 )"
	local uptime="$(  cat $tmpDir/bmxOI.out | awk -F'uptime=' '{print $2}' | cut -d' ' -f1 )"


	local mmOI=$(cat $tmpDir/topOI.out | awk -F'mem=' '{print $2}'| cut -d' ' -f1)
	local cpOI=$(cat $tmpDir/topOI.out | awk -F'cpu=' '{print $2}'| cut -d' ' -f1)
	local idOI=$(cat $tmpDir/topOI.out | awk -F'idl=' '{print $2}'| cut -d' ' -f1)
	local txPI=$(cat $tmpDir/tcpOI.out | awk -F'txP=' '{print $2}'| cut -d' ' -f1)
	local txBI=$(cat $tmpDir/tcpOI.out | awk -F'txB=' '{print $2}'| cut -d' ' -f1)
	local rxPI=$(cat $tmpDir/tcpOI.out | awk -F'rxP=' '{print $2}'| cut -d' ' -f1)
	local rxBI=$(cat $tmpDir/tcpOI.out | awk -F'rxB=' '{print $2}'| cut -d' ' -f1)
	local idSI=$(cat $tmpDir/topSI.out | awk -F'idl=' '{print $2}'| cut -d' ' -f1)

	local tpOL=$(cat $tmpDir/tpOL.out  | awk -F'tp='  '{print $2}'| cut -d' ' -f1)
	local rttL=$(cat $tmpDir/tpOL.out  | awk -F'rtt=' '{print $2}'| cut -d' ' -f1)
	local ttlL=$(cat $tmpDir/tpOL.out  | awk -F'ttl=' '{print $2}'| cut -d' ' -f1)
	local txPL=$(cat $tmpDir/tcpOL.out | awk -F'txP=' '{print $2}'| cut -d' ' -f1)
	local txBL=$(cat $tmpDir/tcpOL.out | awk -F'txB=' '{print $2}'| cut -d' ' -f1)
	local rxPL=$(cat $tmpDir/tcpOL.out | awk -F'rxP=' '{print $2}'| cut -d' ' -f1)
	local rxBL=$(cat $tmpDir/tcpOL.out | awk -F'rxB=' '{print $2}'| cut -d' ' -f1)
	local idSL=$(cat $tmpDir/topSL.out | awk -F'idl=' '{print $2}'| cut -d' ' -f1)

	local aHops=$(cat $tmpDir/topo.out | awk -F'aHops=' '{print $2}'| cut -d' ' -f1)
	local bHops=$(cat $tmpDir/topo.out | awk -F'bHops=' '{print $2}'| cut -d' ' -f1)
	local cHops=$(cat $tmpDir/topo.out | awk -F'cHops=' '{print $2}'| cut -d' ' -f1)
	local hopLq=$(cat $tmpDir/topo.out | awk -F'lq=' '{print $2}'| cut -d' ' -f1)
	local hopLl=$( (tc qdisc show | grep "parent 1:$(printf %x $hopLq)" | grep -oe "loss [0-9]*%" || echo "loss 0%") |  grep -oe "[0-9]*" | sort -u | head -n1)

	local lTime=$(cat $tmpDir/trace.out | awk -F'lTime=' '{print $2}'| cut -d' ' -f1)
	local fTime=$(cat $tmpDir/trace.out | awk -F'fTime=' '{print $2}'| cut -d' ' -f1)


	FORMAT="%16s %16s %8s %5s %9s   %6s %6s %6s %20s %11s %11s %11s %9s   %5s %10s %6s %3s   %4s %4s %6s %4s %4s %4s   %8s %8s %8s %8s  %8s %8s %8s %8s   %11s %6s   %2s %2s %2s %2s %2s  %11s %11s" 
	FIELDS="start end duration probe revision  Links Routes Nodes linkKeys linkRsa linkDhm nodeRsa updPeriod  txq tp rtt ttl  CPU BCPU Memory idOI idSI idSL  outPps txPL outBps txBL inPps rxPL inBps rxBL  uptime lstDsc   aH bH cH hQ hL   lstFailTime fstSuccTime"
	printf "$FORMAT \n" $FIELDS
	[ -f $resultsFile ] || printf "$FORMAT \n" $FIELDS > $resultsFile
	printf "$FORMAT \n" \
	    $start $(ana_time_stamp) ${duration:-"NA"} $probe ${rev:-"NA"} \
	    ${links:-"NA"} ${routes:-"NA"} ${nodes:-"NA"} ${linkKeys:-"NA"} ${linkRsa:-"NA"} ${linkDhm:-"NA"} ${nodeRsa:-"NA"} ${updPeriod:-"NA"}  \
	    ${txq:-"NA"} ${tpOL:-"NA"} ${rttL:-"NA"} ${ttlL:-"NA"} \
	    ${cpOI:-"NA"} ${bmxCpu:-"NA"} ${mmOI:-"NA"} ${idOI:-"NA"} ${idSI:-"NA"} ${idSL:-"NA"} \
	    ${txPI:-"NA"} ${txPL:-"NA"} ${txBI:-"NA"} ${txBL:-"NA"} ${rxPI:-"NA"} ${rxPL:-"NA"} ${rxBI:-"NA"} ${rxBL:-"NA"} \
	    ${uptime:-"NA"} ${lstDsc:-"NA"} \
	    ${aHops:-"NA"} ${bHops:-"NA"} ${cHops:-"NA"} ${hopLq:-"NA"} ${hopLl:-"NA"} \
	    ${lTime:-"NA"} ${fTime:-"NA"} \
	    | tee -a $resultsFile
}

ana_measure_ovhd_owrt() {

    local resultsFile=${1:-$ANA_RESULTS_FILE}
    local rtLoad=${2:-$ANA_RT_LOAD}
    local updPeriod=${3:-$ANA_UPD_PERIOD}
    local duration=${4:-$ANA_MEASURE_TIME}
    local probes=${5:-$ANA_MEASURE_PROBES}
    local probe=

    local start=$(ana_time_stamp)
    mkdir -p $(dirname $resultsFile)

    rm -rf /tmp/ana.tmp.*
    local tmpDir=$(mktemp -d /tmp/ana.tmp.XXXXXXXXXX)

    if [ "$updPeriod" != "0" ]; then
	local longDuration=$((( (($duration + $ANA_PROBE_SAFE_TIME) * 2 * $probes) + $ANA_MEASURE_GAP  )))
	ana_create_descUpdates_mlc $tmpDir $longDuration $updPeriod <<< /dev/zero
    fi

    sleep $ANA_MEASURE_GAP

    for probe in $(seq 1 $probes); do

	true && (
	    echo "$(ana_time_stamp) bench started"

	    ana_bench_top_owrt $tmpDir/topOI.out $duration 0 &
	    ana_bench_tcp_owrt $tmpDir/tcpOI.out $duration 0 &
	    ana_bench_top_sys  $tmpDir/topSI.out $duration 0 &
	    ana_bmx_stat_ip4   $ANA_DST1_IP4  $tmpDir/bmxOI.out $tmpDir/bmlOI.out &
	    wait

	    [ "$rtLoad" != "0" ] && (
		ana_bench_tp_owrt  $tmpDir/tpOL.out  $((($duration + $ANA_RT_RAISE_TIME))) &
		ana_bench_tcp_owrt $tmpDir/tcpOL.out $duration $ANA_PROBE_DELAY_TIME &
		ana_bench_top_sys  $tmpDir/topSL.out $duration $ANA_PROBE_DELAY_TIME &
		wait
	    )
	    echo "$(ana_time_stamp) bench finished"
	)

	echo "ana_summarize $tmpDir $resultsFile $updPeriod $duration $start $probe"
	ana_summarize $tmpDir $resultsFile $updPeriod $duration $start $probe
    done

    rm -r $tmpDir
    echo "$(ana_time_stamp) waiting for finished descUpdates ... "
    wait
    echo "$(ana_time_stamp) done"

}




ana_init_ovhd_scenarios() {

    killall -w $ANA_PROTO

    ./mlc-init-host.sh
    
    ana_create_nodes
    ana_create_net_owrt
    ana_create_links_owrt
    ana_update_dst
    ana_update_mlc
    ana_create_protos 0
}

ana_set_protos_owrt() {
    local nodes=${1:-$ANA_NODES_DEF}
    local param="${2:-"date"}"

    ssh root@$ANA_DST1_IP4 "$param"
    mlc_loop -la $((( $mlc_min_node + $nodes - 1 ))) -e "$param"
}

ana_run_ovhd_scenarios() {

#    ana_init_ovhd_scenarios

#    ana_create_protos 0
#    ana_get_keys
#    ana_create_keys

    local params=
    local p=
    local results=
    local resultsExtension=
    local round=

    for round in $(seq 1 $ANA_MEASURE_ROUNDS); do

	if [ "$((( $round % 2 )))" = "0" ]; then
	    ANA_LINK_DHM_MAX=40 # maxDhmNeighs 0 vs 40
	    resultsExtension=dhm
	else
	    ANA_LINK_DHM_MAX=0 # maxDhmNeighs 0 vs 40
	    resultsExtension=rsa
	fi
	echo ANA_LINK_DHM_MAX=$ANA_LINK_DHM_MAX

	ana_create_protos 0
	ana_get_keys
	ana_create_keys

	if true; then

	    if true; then
		params="30 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180 190 200"
		params="30 40 60 80 100 120 140 160 180 190 200"
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsNodes-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt
		for p in $params; do
		    ana_create_protos $p
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    sleep $ANA_STABILIZE_TIME
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD
		done
	    fi

	    if true; then
		params="4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40"
		params="4 10 15 20 25 30 35 40"
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsLinks-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt 0
		ana_create_protos
		for p in $params; do
		    ana_create_links_owrt $p
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    sleep $ANA_STABILIZE_TIME
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD
		done
	    fi

	    if true; then
		params="30 20 15 10 7 5 4 3 2 1 0.7 0.5 0.4 0.3 0.2"
		params="30 20 15 10 7 5 4 3 2 1 0.7 0.6 0.5"
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsUpdates-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt
		ana_create_protos
		sleep $ANA_STABILIZE_TIME
		for p in $params; do
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD $p
		done
	    fi

	    if true; then
		params="-15 -10 -5 -3 -2 -1"
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsOwnUpdates-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt
		ana_create_protos
		sleep $ANA_STABILIZE_TIME
		for p in $params; do
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD $p
		done
	    fi

	    if true && [ "$ANA_LINK_DHM_MAX" = "0" ]; then
		params="1 2 3 4 5" #1:512, 2:768, 3:896, 4:1024, 5:1536, 6:2048
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsTxCrypt-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt
		ana_create_protos
		for p in $params; do
		    ana_set_protos_owrt $ANA_NODES_DEF "bmx7 -c linkRsaKey=$p"
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    sleep $ANA_STABILIZE_TIME
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD
		done

	    elif true && [ "$ANA_LINK_DHM_MAX" = "40" ]; then
		params="17 18" #16:DH1024M112, 17:DH2048M112, 18:DH3072M112
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsTxCrypt-$resultsExtension"
		ana_create_protos 0
		ana_create_links_owrt
		ana_create_protos
		for p in $params; do
		    ana_set_protos_owrt $ANA_NODES_DEF "bmx7 -c linkDhmKey=$p"
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    sleep $ANA_STABILIZE_TIME
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD
		done
	    fi

	    if true; then
		params="1 2 3 4 5 6 7 8 " #1:512, 2:768, 3:896, 4:1024, 5:1536, 6:2048, 7:3072, 8:4096
		results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsIdCrypt-$resultsExtension"
		ana_create_links_owrt
		for p in $params; do
		    ana_create_protos 0
		    ana_get_keys    $p
		    ana_create_keys
		    ana_create_protos $ANA_NODES_DEF $p 
		    echo "$(ana_time_stamp) MEASURING to $results p=$p of $params"
		    sleep $ANA_STABILIZE_TIME
		    ana_measure_ovhd_owrt $results $ANA_RT_LOAD
		done
	    fi

	fi
    done
}





sec_create_protos_mlc() {
    local nodes=${1:-$ANA_NODES_DEF}

    local ANA_MLC_CMD="rm -rf /root/bmx7/*; mkdir -p /root/bmx7; cd /root/bmx7; ulimit -c 20000; \
   $ANA_PROTO_CMD plugin=bmx7_evil.so nodeRsaKey=$ANA_NODE_KEY_LEN /keyPath=/etc/bmx7/rsa.$ANA_NODE_KEY_LEN $ANA_MAIN_OPTS maxDhmNeighs=$ANA_LINK_DHM_MAX $ANA_MLC_DEVS txBucketDrain=100  \
   > /root/bmx7/bmx7.log 2>&1 &"

    if [ "$nodes" = "0" ]; then
	killall -w $ANA_PROTO

    else

	[ $nodes -lt $ANA_NODES_MAX ] && \
	    mlc_loop -i $((( 1000 + $nodes ))) -a $((( 1000 + $ANA_NODES_MAX - 1))) -e "killall -w $ANA_PROTO"

# ANA_PROTO_RM:
	rm -f $ANA_MLC_DIR/rootfs/mlc*/rootfs/etc/config/bmx7

#	local bmxPs=$(ps aux | grep "$ANA_PROTO_CMD" | grep -v grep | wc -l)

#	[ $nodes -gt $bmxPs ] && \
#	    mlc_loop -li $(((1000 + $bmxPs ))) -a $((( 1000 + $nodes - 1))) -e "$ANA_MLC_CMD"
	mlc_loop -li $((( 1000 ))) -a $((( 1000 + $nodes - 1))) -e "$ANA_MLC_CMD"
    fi
}


sec_create_net() {
    local aHops=${1:-"X"}
    local bHops=${2:-"X"}
    local cHops=${3:-"X"}
    local lq=${4:-"3"}

    mlc_net_flush
    # mlc_configure_grid 1 $lq 0 0 0 1 $ANA_NODE_MAX 1010 $lq 0 0 10 1
    mlc_configure_line 1 $lq 0 1008 $lq 0 1001 0
    mlc_configure_line 1 $lq 0 1018 $lq 0 1011 0
    mlc_configure_line 1 $lq 0 1028 $lq 0 1021 0

    mlc_link_set 1 1000 1 1001 $lq $lq 0
    mlc_link_set 1 1000 1 1011 $lq $lq 0
    mlc_link_set 1 1000 1 1021 $lq $lq 0

    mlc_link_set 1 1010 1 1001 $lq $lq 0
    mlc_link_set 1 1010 1 1011 $lq $lq 0
    mlc_link_set 1 1010 1 1021 $lq $lq 0

    mlc_link_set 1 1020 1 1001 $lq $lq 0
    mlc_link_set 1 1020 1 1011 $lq $lq 0
    mlc_link_set 1 1020 1 1021 $lq $lq 0


    [[ "$aHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1009 1 100${aHops} $lq $lq 0
    [[ "$bHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1009 1 101${bHops} $lq $lq 0
    [[ "$cHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1009 1 102${cHops} $lq $lq 0

    [[ "$aHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1019 1 100${aHops} $lq $lq 0
    [[ "$bHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1019 1 101${bHops} $lq $lq 0
    [[ "$cHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1019 1 102${cHops} $lq $lq 0

    [[ "$aHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1029 1 100${aHops} $lq $lq 0
    [[ "$bHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1029 1 101${bHops} $lq $lq 0
    [[ "$cHops" =~  ^[0-8]$ ]] && mlc_link_set 1 1029 1 102${cHops} $lq $lq 0
}

sec_set_trust() {
    local pattern="${1:-""}"
    local dir=${2:-"/$ANA_NODE_TRUSTED_DIR"} 
    local dirType=${3:-"trustedNodesDir"} 
    local allNodes="$(seq $mlc_min_node $((($mlc_min_node - 1 + $ANA_NODES_MAX))) )  $ANA_DSTS_IP4"

    for anaId in $allNodes; do
	if echo "$anaId" | grep -qe "$pattern"; then
	    local anaIp="$( echo "$ANA_DSTS_IP4" | grep -o "$anaId" || MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"
	    echo ssh root@$anaIp "bmx7 -c $dirType=$dir"
	    $mlc_ssh root@$anaIp "bmx7 -c $dirType=$dir"
	fi
    done
}

sec_get_keys() {

    local roleColor=${1:-"all-trusted-nodes"}
    local pattern="${2:-""}"
    local keysDir="$ANA_MLC_KEYS_DIR/${roleColor}"
    local allNodes="$(seq $mlc_min_node $((($mlc_min_node - 1 + $ANA_NODES_MAX))) )  $ANA_DSTS_IP4"
    local anaId=

    echo "roleColor=$roleColor pattern=$pattern keysDir=$keysDir"

    mkdir -p $keysDir
    rm -v $keysDir/*RSA*

    for anaId in $allNodes; do
	if echo "$anaId" | grep -qe "$pattern"; then
	    local anaIp="$( echo "$ANA_DSTS_IP4" | grep -o "$anaId" || MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"

	    
	    local nodeId="$(   sec_get_dbItem $anaIp id   mlcIp )"; nodeId=${nodeId:-"-"}
	    local nodeKey="$(  sec_get_dbItem $anaIp rsa  mlcIp )"; nodeKey=${nodeKey:-"-"}
	    local nodeName="$( sec_get_dbItem $anaIp name mlcIp )"; nodeName=${nodeName:-"-"}

	    echo "nodeId=$nodeId  nodeName=$nodeName nodeKey=$nodeKey"
	    touch $keysDir/$nodeId.$nodeName.$nodeKey
	fi
    done
    
    ls -l $keysDir/

}


sec_prepare_trust() {

    local APattern=${1:-"^10[0-0][0-9]$"} # trusteds
    local aPattern=${2:-"^100[0,9]$"}     # trustees

    local BPattern=${3:-"^10[0-2][0-9]$"}
    local bPattern=${4:-"^101[0,9]$"}

    local CPattern=${5:-"^10[1-2][0-9]$"}
    local cPattern=${6:-"^102[0,9]$"}

    local ZPattern=${7:-"^XXX$"}
    local zPattern=${7:-"^10[0-2][1-8]$"}


    sec_set_trust "" "-" "trustedNodesDir"
#   sec_set_trust "" "/$ANA_NODE_TRUSTED_DIR" "trustedNodesDir"

    sec_get_keys z-trusted-nodes "$ZPattern"
    ana_create_keys  z-trusted-nodes "$zPattern" $ANA_NODE_TRUSTED_DIR

    sec_get_keys a-trusted-nodes "$APattern"
    ana_create_keys  a-trusted-nodes "$aPattern" $ANA_NODE_TRUSTED_DIR

    sec_get_keys b-trusted-nodes "$BPattern"
    ana_create_keys  b-trusted-nodes "$bPattern" $ANA_NODE_TRUSTED_DIR

    sec_get_keys c-trusted-nodes "$CPattern"
    ana_create_keys  c-trusted-nodes "$cPattern" $ANA_NODE_TRUSTED_DIR

}

sec_prepare_attacks() {

    local APattern=${1:-"^1020$"} # attackeds
    local aPattern=${2:-"^10[0-0][0-9]$"} # attacker

    local BPattern=${3:-"^10[0,2]0$"}
    local bPattern=${4:-"^10[1-1][0-9]$"}

    local CPattern=${5:-"^1000$"}
    local cPattern=${6:-"^10[2-2][0-9]$"}

#   sec_set_trust "" "-" "attackedNodesDir"
    sec_set_trust "" "/$ANA_NODE_ATTACKED_DIR" "attackedNodesDir"

    sec_get_keys a-attacked-nodes "$APattern"
    ana_create_keys  a-attacked-nodes "$aPattern" $ANA_NODE_ATTACKED_DIR
    sec_set_trust "$aPattern" 1 evilRouteDropping
    sec_set_trust "$aPattern" 1 evilDescDropping
#   sec_set_trust "$aPattern" 1 evilOgmDropping
#   sec_set_trust "$aPattern" 1 evilOgmMetrics

    sec_get_keys b-attacked-nodes "$BPattern"
    ana_create_keys  b-attacked-nodes "$bPattern" $ANA_NODE_ATTACKED_DIR
    sec_set_trust "$bPattern" 1 evilRouteDropping
    sec_set_trust "$bPattern" 0 evilDescDropping

    sec_get_keys c-attacked-nodes "$CPattern"
    ana_create_keys  c-attacked-nodes "$cPattern" $ANA_NODE_ATTACKED_DIR
    sec_set_trust "$cPattern" 1 evilRouteDropping
    sec_set_trust "$cPattern" 1 evilDescDropping
}


sec_get_nodeDb() {

    local dbFile=${1:-"$ANA_NODE_DB_FILE"}
    local allNodes="$(seq $mlc_min_node $((($mlc_min_node - 1 + $ANA_NODES_MAX))) )  $ANA_DSTS_IP4"
    local anaId=

    echo updating dbFile=$dbFile

    rm -fv $dbFile

    for anaId in $allNodes; do

	local anaIp="$( echo "$ANA_DSTS_IP4" | grep -o "$anaId" || MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"
	local nodeVersion="$( $mlc_ssh root@$anaIp "bmx7 -c version list=interfaces | grep -e version=BMX -e dev= | head -n2; ip a show dev eth0 | grep 'inet 10.0.' " )"
	local nodeId="$( echo "$nodeVersion" | awk -F'id=' '{print $2}' | cut -d' ' -f1 )"; nodeId=${nodeId:-"-"}
	local nodeKey="$( echo "$nodeVersion" | awk -F'nodeKey=' '{print $2}' | cut -d' ' -f1 )"; nodeKey=${nodeKey:-"-"}
	local nodeIp="$( echo "$nodeVersion" | awk -F'ip=' '{print $2}' | cut -d' ' -f1 )"; nodeIp=${nodeIp:-"-"}
	local nodeName="$( echo "$nodeVersion" | awk -F'hostname=' '{print $2}' | cut -d' ' -f1 )"; nodeName=${nodeName:-"-"}
	local nodeMac="$( echo "$nodeVersion" | grep dev= | awk -F'localMac=' '{print $2}' | cut -d' ' -f1 )"; nodeMac=${nodeMac:-"-"}
	local nodeDev="$( echo "$nodeVersion" | grep dev= | awk -F'dev=' '{print $2}' | cut -d' ' -f1 )"; nodeDev=${nodeDev:-"-"}
	local mlcIp="$( echo "$nodeVersion" | grep inet | awk '{print $2}' | cut -d'/' -f1 )"; mlcIp=${mlcIp:-"-"}
	echo "nodeVersion=$nodeVersion:"
	echo "id=$nodeId ip6=$nodeIp name=$nodeName rsa=$nodeKey dev=$nodeDev mac=$nodeMac mlcIp=$mlcIp" | tee -a $dbFile
    done
    
}

sec_get_dbItem() {

    local pattern="${1:-""}"
    local outField=${2:-"ip6"}
    local inField=${3:-"name"}
    local dbFile=${4:-"$ANA_NODE_DB_FILE"}

    local nodeInfo="$(grep -e "${inField}=${pattern}"  $dbFile)"

#   echo "nodeInfo=$nodeInfo"
    
    if [ -z "$nodeInfo" ]; then
	return 1
    else
	echo "$nodeInfo" | awk -F"$outField=" '{print $2}' | cut -d' ' -f1
    fi

}

sec_tcpdump() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local delay=${3:-$ANA_PROBE_DELAY_TIME}
    local opts="$4"

    echo "sec_tcpdump $$"

    sleep $delay
    echo timeout $duration tcpdump -nve -i $mlc_bridge_prefix$ANA_MBR -s 200 $( [ "$opts" ] && echo "$opts" )  > $outFile 2>&1
    tcpdump -nvvve -i $mlc_bridge_prefix$ANA_MBR -s 200 -w $outFile $( [ "$opts" ] && echo "$opts" )
#    tshard -a duration:$duration -i $mlc_bridge_prefix$ANA_MBR -s 200 -w $outFile
}


sec_tcpdump_filter() {
    local inFile=${1:-"/tmp/test"}
    local patterns=${2:-"mlc1000"}
    local grepCond=${3:-"v"}
    local outField=${4:-"mac"}
    local inField=${5:-"name"}
    local dbFile=${6:-"$ANA_NODE_DB_FILE"}

    local inData="$(tcpdump -r $inFile -nevv -ttttt 2>/dev/null | grep icmp6)"

    echo "Filter $grepCond results inFile=$inFile patterns=$patterns :"

    for p in $patterns; do
	inData="$(echo "$inData" | grep -$grepCond " > $(sec_get_dbItem $p $outField $inField)")"
    done
    echo "$inData"
}

sec_tcpdump_translate() {
    local inFile=${1:-"/tmp/test"}
    local patterns=${2:-"mlc"}
    local inField=${4:-"mac"}
    local outField=${5:-"name"}
    local dbFile=${6:-"$ANA_NODE_DB_FILE"}

    local inData="$(cat $inFile)"

    for n in $(sec_get_dbItem mlc name name); do
	local m=$(sec_get_dbItem $n $inField $outField)
	inData=$(echo "$inData" | sed s/"$m"/"$n"/)
    done
    echo "$inData"
}

sec_ping_e2e() {

    local outFile=${1:-"/tmp/ana.trace"}
    local duration=${2:-$ANA_MEASURE_TIME}
    local srcMlcId=${3:-"1009"}
    local dstMlcId=${4:-"1000"}
    
    local srcMlcIp=$(sec_get_dbItem "mlc${srcMlcId}" "mlcIp" "name")
    local srcNodeIp=$(sec_get_dbItem "mlc${srcMlcId}" "ip6"   "name")
    local dstNodeIp=$(sec_get_dbItem "mlc${dstMlcId}" "ip6"   "name")

    echo "sec_ping_e2e $$"
    rm -f $outFile

    if [ "$srcMlcIp" ] && [ "$srcNodeIp" ] && [ "$dstNodeIp" ] ; then

	sec_tcpdump $outFile $duration 0 "port 6270 or (icmp6 and src $srcNodeIp and dst $dstNodeIp and ip6[40]=128 and ip6[7]<=30)" &
	sleep 0.1
	time $ANA_SSH root@$srcMlcIp "timeout $duration sh -c \"while date && echo newEchoRound && ! ping6 -t 30 -n -i 0.1 $dstNodeIp; do sleep 0.1; done\""
	sleep 1.5
	sync
	killall -15 tcpdump
	wait
	echo "$outFile :"
	ls -l $outFile
#	tshark -r $outFile
#	tcpdump -r $outFile -nve -ttttt

	sec_tcpdump_filter $outFile "randomASDF" e > $outFile.all
#	sec_tcpdump_translate $outFile.all | less

	echo "Last Failed packets:"
	sec_tcpdump_filter $outFile "$( for s in $(seq $dstMlcId $srcMlcId); do echo -n "mlc$s "; done )" v > $outFile.v
	local lCatched="$(sec_tcpdump_translate $outFile.v | grep -v "Filter" | tail -n1)"
	local lTime="$(echo "$lCatched" | cut -d' ' -f1 | cut -d':' -f3)"
	local lSeq="$(echo "$lCatched"  | awk -F'seq ' '{print $2}' )"
	local lHlim="$(echo "$lCatched"  | awk -F'hlim ' '{print $2}' | cut -d ',' -f1 )"
	local lTxNode="$(echo "$lCatched" | cut -d' ' -f2)"
	local lRxNode="$(echo "$lCatched" | cut -d' ' -f4)"

	echo "First Succeeded packets:"
	sec_tcpdump_filter $outFile "mlc${dstMlcId}" e > $outFile.e
	local fCatched="$(sec_tcpdump_translate $outFile.e | grep -v "Filter" | head -n1)"
	local fTime="$(echo "$fCatched" | cut -d' ' -f1 | cut -d':' -f3)"
	local fSeq="$(echo "$fCatched"  | awk -F'seq ' '{print $2}' )"
	local fHlim="$(echo "$fCatched"  | awk -F'hlim ' '{print $2}' | cut -d ',' -f1 )"
	local fTxNode="$(echo "$fCatched" | cut -d' ' -f2)"
	local fRxNode="$(echo "$fCatched" | cut -d' ' -f4)"

	echo "srcMlcId=$srcMlcId dstMlcId=$dstMlcId   lTime=$lTime lSeq=$lSeq lHlim=$lHlim lTxNode=$lTxNode lRxNode=$lRxNode   fTime=$fTime fSeq=$fSeq fHlim=$fHlim fTxNode=$fTxNode fRxNode=$fRxNode" > $outFile.out

    fi
}

sec_init_attack_scenarios() {


    ./mlc-init-host.sh
    ana_create_nodes
    mlc_net_flush
    sec_create_protos_mlc 0
    sec_create_protos_mlc
    sec_get_nodeDb
}

sec_measure_attack_scenario() {
    local aHops=${1:-"X"}
    local bHops=${2:-"X"}
    local cHops=${3:-"X"}
    local lq=${4:-"3"}
    local resultsFile=${5:-$ANA_RESULTS_FILE}

    local updPeriod=0
    local duration=$ANA_MEASURE_TIME
    local probes=$ANA_MEASURE_PROBES
    local probe=

    mkdir -p $(dirname $resultsFile)

    sleep $ANA_MEASURE_GAP

    for probe in $(seq 1 $probes); do

	local start=$(ana_time_stamp)

	rm -rf /tmp/ana.tmp.*
#	mv /tmp/ana.tmp.* /tmp/ana.last
#	local tmpDir=$(mktemp -d /tmp/ana.tmp.XXXXXXXXXX)
	local tmpDir="/tmp/ana.tmp.$start"
	mkdir -p $tmpDir
	rm $tmpDir/*

	mlc_net_flush
	sec_set_trust "" "" "flushAll trustedNodesDir=- attackedNodesDir=-"
	sec_prepare_trust
	sec_create_net $aHops $bHops $cHops 3
	local sd="$((( $ANA_STABILIZE_TIME + $(mlc_rand 5) ))).$(mlc_rand 9)"
	echo "Wating $sd sec to establish topology"
	sleep $sd

	echo
	echo "Adjusting topology link qualities"
	sec_create_net $aHops $bHops $cHops $lq
	echo "aHops=$aHops bHops=$bHops cHops=$cHops lq=$lq" > $tmpDir/topo.out
    

	echo
	echo "Creating attacks"
	sec_prepare_attacks

	echo
	echo "Starting ping"
	sec_ping_e2e $tmpDir/trace $duration 1009 1000 &
	sec_set_trust "^10[0-0][0,9]$" "/$ANA_NODE_TRUSTED_DIR" "trustedNodesDir"

	true && (
	    echo "$(ana_time_stamp) bench started"
#	    ana_bench_top_owrt $tmpDir/topOI.out $duration 0 &
#	    ana_bench_tcp_owrt $tmpDir/tcpOI.out $duration 0 &
	    ana_bench_top_sys  $tmpDir/topSI.out $duration 0 &
	    ana_bmx_stat_ip4   10.0.10.9 $tmpDir/bmxOI.out $tmpDir/bmlOI.out &
	    wait
	    echo "$(ana_time_stamp) bench finished"
	)

	wait
	ana_summarize $tmpDir $resultsFile $updPeriod $duration $start $probe
    done

}

sec_run_attack_scenarios() {

    sec_init_attack_scenarios

    for round in $(seq 1 $ANA_MEASURE_ROUNDS); do

	local losses="3 5 7 9 11 13 15"
#	local losses="3 7 11 15"

	if false; then
	    local resultsFile="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-recoveryVsLoss"
	    for l in $losses; do
		time sec_measure_attack_scenario 8 X 1 $l $resultsFile
	    done
	fi

	local losses="3 5 7 9 11 13 15"
	local losses="9 11 13 15"

	for l in $losses; do

	    local params="1 2 3 4 5 6 7 8 X"
#	    local params="1 3 5 8 X"

	    if true; then
		local resultsFile="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-recoveryVsTrustHops-$l"
		for p in $params; do
		    time sec_measure_attack_scenario $p X 1 $l $resultsFile
		done
	    fi

	    if true; then
		local resultsFile="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-recoveryVsEvilHops-$l"
		for p in $params; do
		    time sec_measure_attack_scenario 8 X $p $l $resultsFile
		done
	    fi
	    
	    if true; then
		local resultsFile="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-recoveryVsSuppHops-$l"
		for p in $params; do
		    time sec_measure_attack_scenario 8 $p 1 $l $resultsFile
		done
	    fi

	done
    done
}



ana_fetch_node_role() {

    local anaId=${1:-$mlc_min_node}
    local penLevel=${2:-$ANA_ATTACK_PEN_LEVEL}
    local rsaLen=${3:-"$ANA_NODE_KEY_LEN"}

    local anaIp="$(MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"
    local nodeName="${mlc_name_prefix}${anaId}"
    local nodeVersion="$( $mlc_ssh root@$anaIp "( bmx7 -c version || bmx7 nodeRsaKey=$rsaLen /keyPath=/etc/bmx7/rsa.$rsaLen version ) | grep version=BMX" )"
    local nodeId="$( echo "$nodeVersion" | awk -F'id=' '{print $2}' | cut -d' ' -f1 )"; nodeId=${nodeId:-"-"}
    local nodeIp="$( echo "$nodeVersion" | awk -F'ip=' '{print $2}' | cut -d' ' -f1 )"; nodeIp=${nodeIp:-"-"}

    local topoColsPerRole=$((( $ANA_ATTACK_TOPO_COLS / $ANA_ATTACK_TOPO_ROLES )))
    local nodeIdx=$((( $anaId - $mlc_min_node )))
    local nodeCol=$((( $nodeIdx % $ANA_ATTACK_TOPO_COLS )))
    local nodeLine=$((( $nodeIdx / $ANA_ATTACK_TOPO_COLS )))
    local topoLines=$((( $ANA_NODES_MAX / $ANA_ATTACK_TOPO_COLS )))
    local topoLineTop=0
    local topoLineBottom=$((( $topoLines - 1 )))
    local nodeRoleLMin=$((( $nodeCol / $topoColsPerRole )))
    local nodeRoleLMax=$nodeRoleLMin
    local nodeRole=$nodeRoleLMin
    local rolePenetrationLines=$((( ($topoLines-2) / $ANA_ATTACK_TOPO_ROLES )))


    if [ $nodeLine -gt $topoLineTop ] && [ $nodeLine -lt  $topoLineBottom ]; then

	nodeRoleLMax=$((( ( $nodeLine - 1 ) / $rolePenetrationLines )))

	local leftL0ColBound=$((( $nodeRoleLMax * $topoColsPerRole )))
	local leftLxColBound=$((( $leftL0ColBound - $penLevel )))
	local rightL0ColBound=$((( $leftL0ColBound + $topoColsPerRole - 1 )))
	local rightLxColBound=$((( $rightL0ColBound + $penLevel )))

	local fixedNodeCol=$nodeCol

	if [ $leftLxColBound -lt 0 ] && [ $nodeCol -ge $((( $ANA_ATTACK_TOPO_COLS - $penLevel ))) ]; then
	    fixedNodeCol=$((( $nodeCol - $ANA_ATTACK_TOPO_COLS )))
	fi
	
	if [ $rightLxColBound -ge $ANA_ATTACK_TOPO_COLS ] && [ $nodeCol -le $((( $penLevel - 1 ))) ]; then
	    fixedNodeCol=$((( $nodeCol + $ANA_ATTACK_TOPO_COLS )))
	fi

	if [ $fixedNodeCol -ge $leftLxColBound ] && [ $fixedNodeCol -le $rightLxColBound ]; then
	    nodeRole=$nodeRoleLMax
	fi

    fi


   [ $nodeIdx -eq 0 ] &&\
    printf "$ANA_ROLE_FILE_FORMAT" $ANA_ROLE_FILE_HEADER >&2
    printf "$ANA_ROLE_FILE_FORMAT" $ANA_ATTACK_TOPO_COLS $ANA_NODES_MAX $penLevel $anaId $anaIp $nodeName $nodeId $nodeIp $nodeCol $nodeLine $nodeRoleLMin $nodeRoleLMax $nodeRole ${ANA_ATTACK_ROLE_COLORS[$nodeRole]}
}

ana_fetch_role() {

    local penLevel=${1:-$ANA_ATTACK_PEN_LEVEL}
    local rsaLen=${2:-"$ANA_NODE_KEY_LEN"}
    local roleFile="$ANA_ATTACK_OF_DIR/$ANA_ATTACK_OF_PREFIX-$penLevel"

    local i=

    mkdir -p $ANA_ATTACK_OF_DIR
    rm -f $roleFile

    for i in $(seq $mlc_min_node $ANA_NODE_MAX); do
	
	local line="$(ana_fetch_node_role $i $penLevel $rsaLen )"
	echo "$line" >> $roleFile 
	echo "$line"
	printf "%d" $(echo "$line" | awk '{print $13}')

	[ $((( ($i + 1 - $mlc_min_node) % $ANA_ATTACK_TOPO_COLS ))) -eq 0 ] && echo

    done
    echo
}

ana_fetch_roles() {
    local penLevels=${1:-"$((( $ANA_ATTACK_TOPO_COLS / $ANA_ATTACK_TOPO_ROLES )))"}
    local rsaLen=${2:-"$ANA_NODE_KEY_LEN"}
    local i=

    for i in $(seq 0 $penLevels); do
	ana_fetch_role $i $rsaLen
    done

}

ana_create_role_dir_links() {

    local penLevel=${1:-$ANA_ATTACK_PEN_LEVEL}
    local roleFile="$ANA_ATTACK_OF_DIR/$ANA_ATTACK_OF_PREFIX-$penLevel"
    local subjectLine=

    rm -rf $ANA_MLC_DIR/rootfs/mlc1*/rootfs/$ANA_NODE_TRUSTED_DIR
    rm -rf $ANA_MLC_DIR/rootfs/mlc1*/rootfs/$ANA_NODE_ATTACKED_DIR

    
    while read -r subjectLine; do
	local subjectLineArray=($subjectLine)
	
	local subjectMlcId=${subjectLineArray[$ANA_ROLE_FILE_COL_MLCID]}
	local subjectName=${subjectLineArray[$ANA_ROLE_FILE_COL_NAME]}
	local subjectRole=${subjectLineArray[$ANA_ROLE_FILE_COL_NODEROLE]}
	local subjectRoleColor=${ANA_ATTACK_ROLE_COLORS[$subjectRole]}

	echo "checking: subjectRole=$subjectRoleColor subject: mlcId=$subjectMlcId name=$subjectName role=$subjectRole"
	
	if [ $subjectMlcId -le $ANA_NODE_MAX ]; then
	    ln -s /$ANA_NODE_KEYS_DIR/$subjectRoleColor-trusted-nodes   $ANA_MLC_DIR/rootfs/$subjectName/rootfs/$ANA_NODE_TRUSTED_DIR
	    ln -s /$ANA_NODE_KEYS_DIR/$subjectRoleColor-attacked-nodes  $ANA_MLC_DIR/rootfs/$subjectName/rootfs/$ANA_NODE_ATTACKED_DIR
	fi
    done < $roleFile
}

ana_get_role_behavior() {
    declare -a argTable=("${!1}")
    local line_subjectRole=$2
    local col_objectRole=$3

    local item=$((( $line_subjectRole * $ANA_ATTACK_TOPO_ROLES + $col_objectRole )))
    
    [ "${argTable[$item]}"  = "1" ] &&  true ||  false 
}

ana_test_get_role_behavior() {

    local c=
    local l=

    for c in $(seq 0 2); do
	for l in $(seq 0 2); do
	    printf "%d" $( ana_get_role_behavior ANA_TRUST_TABLE[@] $l $c && echo 1 || echo 0 )
	done
	echo
    done

   [ "$1"  = "1" ] &&  true ||  false 
}


ana_create_role_key_dirs() {

    local penLevel=${1:-$ANA_ATTACK_PEN_LEVEL}
    local roleFile="$ANA_ATTACK_OF_DIR/$ANA_ATTACK_OF_PREFIX-$penLevel"
    local subjectRole=
    local objectLine=

    for subjectRole in $(seq 0 $((( $ANA_ATTACK_TOPO_ROLES - 1))) ); do
	local subjectRoleColor=${ANA_ATTACK_ROLE_COLORS[$subjectRole]}
	local trustedNodesDir="$ANA_MLC_KEYS_DIR/$subjectRoleColor-trusted-nodes"
	local attackedNodesDir="$ANA_MLC_KEYS_DIR/$subjectRoleColor-attacked-nodes"

	mkdir -p $trustedNodesDir
	rm -f $trustedNodesDir/*
	mkdir -p $attackedNodesDir
	rm -f $attackedNodesDir/*

	while read -r objectLine; do
	    local objectLineArray=($objectLine)
	    
	    local objectMlcId=${objectLineArray[$ANA_ROLE_FILE_COL_MLCID]}
	    local objectName=${objectLineArray[$ANA_ROLE_FILE_COL_NAME]}
	    local objectRole=${objectLineArray[$ANA_ROLE_FILE_COL_NODEROLE]}
	    local objectKey=${objectLineArray[$ANA_ROLE_FILE_COL_NODEID]}

	    echo "checking: subjectRole=$subjectRoleColor object: mlcId=$objectMlcId name=$objectName role=$objectRole key=$objectKey"
	    
	    if [ $objectMlcId -le $ANA_NODE_MAX ]; then
		ana_get_role_behavior ANA_TRUST_TABLE[@]  $subjectRole $objectRole && touch $trustedNodesDir/$objectKey.$objectName
		ana_get_role_behavior ANA_ATTACK_TABLE[@] $subjectRole $objectRole && touch $attackedNodesDir/$objectKey.$objectName
	    fi
	done < $roleFile

    done 

    ana_create_role_dir_links $penLevel
}



ana_enable_trust() {
   local nodeId=${1:-"$ANA_CPA_TRUST_NODES"}
   local id=
   for id in $nodeId; do
       mlc_loop -i $id -e "bmx7 -c trustedNodesDir=/etc/bmx7/trustedNodes"
   done
}

ana_disable_trust() {
   local nodeId=${1:-"$ANA_CPA_TRUST_NODES"}
   local id=
   for id in $nodeId; do
       mlc_loop -i $id -e "bmx7 -c trustedNodesDir=-"
   done
}

ana_enable_cpa_attack() {
   local nodeId=${1:-"$ANA_CPA_ATTACK_NODE"}
   mlc_loop -i $nodeId -e "bmx7 -c evilOgmSqns=1" 
}

ana_disable_cpa_attack() {
   local nodeId=${1:-"$ANA_CPA_ATTACK_NODE"}
   mlc_loop -i $nodeId -e "bmx7 -c evilOgmSqns=-" 
}


ana_measure_e2e_route() {

    local srcNodeId=${1}
    local dstNodeId=${2}
    local penLevel=${3:-"$ANA_ATTACK_PEN_LEVEL"}
    
    local roleFile="$ANA_ATTACK_OF_DIR/$ANA_ATTACK_OF_PREFIX-$penLevel"
    local objectLine=
    local srcMlcIp=
    local dstNodeIp=

    while read -r objectLine; do
	local objectLineArray=($objectLine)
	local objectMlcId=${objectLineArray[$ANA_ROLE_FILE_COL_MLCID]}
	local objectMlcIp=${objectLineArray[$ANA_ROLE_FILE_COL_MLCIP]}
	local objectNodeIp=${objectLineArray[$ANA_ROLE_FILE_COL_NODEIP]}
	
	if [ $objectMlcId -eq $srcNodeId ]; then
	    srcMlcIp=$objectMlcIp
	fi
	if [ $objectMlcId -eq $dstNodeId ]; then
	    dstNodeIp=$objectNodeIp
	fi
    done < $roleFile

    echo "-------------------------------------------" >&2
    echo "srcMlcIp=$srcMlcIp dstNodeIp=$dstNodeIp ..." >&2

    local rtt=$( \
	[ "$srcMlcIp" ] && [ "$dstNodeIp" ] && \
	echo "$($ANA_SSH root@$srcMlcIp "time ping6 -n -i 0.1 -c1 -w $ANA_PING_DEADLINE $dstNodeIp " 2>&1 | grep -e '^real' | grep -e '0m' | cut -d'm' -f2 | cut -d's' -f1 ) * 1000" | bc  -l | cut -d'.' -f1 )
    
    [ "$rtt" ] && [ $rtt -le $((( 1000 * ( $ANA_PING_DEADLINE - 1)))) ] && echo $rtt || echo NA 
}

ana_init_attack_scenarios() {

    ./mlc-init-host.sh

    ana_create_nodes

    ana_create_protos_mlc 0

    ana_fetch_roles

}

ana_configure_grid() {

    local lq=${2:-"$ANA_LQ"}

    mlc_net_flush
#   mlc_configure_grid <dev_idx> [lq] [loop_x_lq] [loop_y_lq] [0=ortographic,1=diagonal] [distance] [max_node]    [min_node]    [rq] [loop_x_rq] [loop_y_rq] [columns]             [purge]
    mlc_configure_grid $ANA_MBR  $lq  $lq         0           0                          1          $ANA_NODE_MAX $mlc_min_node $lq  $lq         0           $ANA_ATTACK_TOPO_COLS 1
}



ana_measure_e2e_recovery() {

    local lq=${1:-$ANA_LQ}
    local penLevel=${2:-$ANA_ATTACK_PEN_LEVEL}
    local srcNodeId=${3}
    local dstNodeId=${4}

    local resultsDir=$ANA_RESULTS_DIR
    local resultsFile=$ANA_RESULTS_FILE_PREFIX

    mkdir -p $resultsDir
    touch $resultsDir/$resultsFile

    ana_disable_trust $dstNodeId
    ana_enable_cpa_attack $ANA_CPA_ATTACK_NODE
    sleep $ANA_STABILIZE_TIME
    ana_enable_trust $dstNodeId &

    local recoveryLatency=$( ana_measure_e2e_route $srcNodeId $dstNodeId )

    echo   "date nodes cols roles penLevel stabTime srcId dstId cpaId latency ttl rtt ovhd sysCpu srcNodeMem dstNodeMem"
    printf "%20  " \
	$(ana_time_stamp) \
	$ANA_NODES_MAX \
	$ANA_ATTACK_TOPO_COLS \
	$ANA_ATTACK_TOPO_ROLES \
	$penLevel \
	$ANA_STABILIZE_TIME \
	$srcNodeId \
	$dstNodeId \
	$ANA_CPA_ATTACK_NODE \
	$recoveryLatency \
	\
	>> $resultsDir/$resultsFile
}


ana_run_attack_scenarios() {

    local lq=${1:-$ANA_LQ}
    local penLevel=${2:-$ANA_ATTACK_PEN_LEVEL}


    ana_create_protos_mlc 0
    ana_create_role_key_dirs $penLevel
    ana_create_protos_mlc 0
    ana_create_protos_mlc $ANA_NODES_MAX

    local srcDstId=
    for srcDstId in $ANA_NODE_PROBE_PAIRS; do
	local srcId=$( echo $srcDstId | cut -d':' -f1 )
	local dstId=$( echo $srcDstId | cut -d':' -f2 )
	
	local results=$( ana_measure_e2e_recovery $lq $penLevel $srcId $dstId )
    done

}

ana_all() {

    local lq=${1:-$ANA_LQ}
    local penLevels=$((( $ANA_ATTACK_TOPO_COLS / $ANA_ATTACK_TOPO_ROLES )))
    local i=

#    ana_init_attack_scenarios

    ana_configure_grid $ANA_NODE_MAX $lq $ANA_ATTACK_TOPO_COLS

    for i in $(seq 0 $penLevels); do
	echo ana_run_attack_scenarios $lq $i
    done
}

################################
# misc...


ana_create_random_set() {

    local NUM=${1:-50}
    local FROM=${2:-100}

    local IN="$(seq 0 $(($FROM-1)) )"
    local OUT=

    for i in $(seq 1 $NUM); do
#	echo "IN=$IN"
	
	local R=$(./ana_rand.sh 1 $(($FROM+1-$i)) )
#	echo "COL=$R"

	local VAL=$(echo "$IN" | sed -n ${R}p )
#	echo "VAL=$VAL"
	
	if [ "$OUT" ]; then
	    OUT="$OUT $VAL"
	else
	    OUT="$VAL"
	fi
#	echo "OUT=$OUT"

	IN="$(echo "$IN" | sed  "${R}d" )"

    done
    
    echo "$OUT"
}

ana_create_random_keys() {
    local NUM=${1:-50}
    local FROM=${1:-$ANA_NODES_DEF}

    local keysPath=$ANA_MLC_KEYS_DIR/

    local keysSortedAll="$(for f in $(ls -l $keysPath/ | grep -o -e "mlc...." -e "o101" | sort); do (cd $keysPath && ls *.$f); done)"
    
    local keysSortedFrom="$(echo "$keysSortedAll" | head -n $FROM)"

    for i in $(seq 1 $NUM); do
	let from=$FROM+1-$i

	pickId=$(./ana_rand 1 $from )
    done


}
