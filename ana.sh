#!/bin/bash
set +x

. ./mlc-vars.sh
mlc_cpu_idle_assumption=35
#set -x

ANA_SSH="$mlc_ssh -i /home/neumann/.ssh/id_rsa "
ANA_MLC_DIR="/home/neumann/mlc-public.git"
ANA_OWRT_DIR="/home/neumann/openwrt/openwrt-15.05.git"
ANA_RESULTS_DIR="$ANA_MLC_DIR/ana"
ANA_RESULTS_FILE_PREFIX="results-01"
ANA_PROT_DIR="/usr/src/bmx6.git"
ANA_NODE_TRUSTED_DIR="etc/bmx6/trustedNodes"
ANA_NODE_ATTACKED_DIR="etc/bmx6/attackedNodes"
ANA_NODE_KEYS_DIR="usr/src/bmxKeys"
ANA_MLC_KEYS_DIR=$ANA_MLC_DIR/rootfs/mlc0002/rootfs/$ANA_NODE_KEYS_DIR

ANA_NODES_DEF=100 # 100
ANA_NODES_MIN=10

ANA_LINKS_DEF=4
ANA_LINKS_MIN=1
ANA_LINKS_MAX=20

ANA_LINK_KEY_LEN=896
ANA_NODE_KEY_LEN=3072


ANA_MBR=1
ANA_LQ=3
ANA_PROTO=bmx6
ANA_PROTO_RM="/usr/lib/bmx6* /etc/config/bmx6"
ANA_MLC_DEVS="dev=eth1"
#ANA_DST_DEVS="dev=br-lan dev=wlan0 /l=1"
ANA_DST_DEVS="dev=br-lan"

ANA_MAIN_CMD="bmx6 d=0"
ANA_UDP_PORT="6240"

################################
# for attack scenarios:
ANA_NODES_MAX=165 # 150
ANA_ATTACK_PEN_LEVEL=0
ANA_ATTACK_TOPO_COLS=15
ANA_ATTACK_TOPO_ROLES=3
ANA_MAIN_OPTS="plugin=bmx6_evil.so nodeSignatureLen=$ANA_NODE_KEY_LEN /keyPath=/etc/bmx6/rsa.$ANA_NODE_KEY_LEN linkSignatureLen=$ANA_LINK_KEY_LEN trustedNodesDir=/$ANA_NODE_TRUSTED_DIR attackedNodesDir=/$ANA_NODE_ATTACKED_DIR evilRouteDropping=1 evilDescDropping=1"
ANA_MLC_CMD="$ANA_MAIN_CMD $ANA_MAIN_OPTS $ANA_MLC_DEVS >/root/bmx6.log& sleep 3"

# for owrt perf scenarios:
ANA_NODES_MAX=180
ANA_ATTACK_PEN_LEVEL=0
ANA_ATTACK_TOPO_COLS=10
ANA_ATTACK_TOPO_ROLES=1
ANA_MAIN_OPTS="nodeSignatureLen=$ANA_NODE_KEY_LEN /keyPath=/etc/bmx6/rsa.$ANA_NODE_KEY_LEN linkSignatureLen=$ANA_LINK_KEY_LEN trustedNodesDir=/$ANA_NODE_TRUSTED_DIR"
ANA_DST_CMD="$ANA_MAIN_CMD $ANA_MAIN_OPTS $ANA_DST_DEVS >/root/bmx6.log&"
ANA_MLC_CMD="rm -rf /root/bmx6/*; mkdir -p /root/bmx6; cd /root/bmx6; ulimit -c 20000; $ANA_MAIN_CMD $ANA_MAIN_OPTS $ANA_MLC_DEVS > /root/bmx6/bmx6.log 2>&1 &"
################################


ANA_DST_DEV=eth1
ANA_DST_SRC=192.168.1.76/24
ANA_DST1_MAC=14:cf:92:52:0f:10
ANA_DST1_IP4=192.168.1.101
ANA_DST2_MAC=14:cf:92:52:13:a6
ANA_DST2_IP4=192.168.1.102
ANA_DST_SYS=""
ANA_DST_PACKAGES="$ANA_OWRT_DIR/bin/ar71xx/packages/routing/bmx7_*.ipk"
ANA_DST_FILES=""


ANA_E2E_DST=mlc1003
ANA_E2E_SRC4=10.0.10.0

ANA_PING_DEADLINE=20
ANA_STABILIZE_TIME=120
ANA_MEASURE_TIME=30
ANA_MEASURE_GAP=10
ANA_UPD_PERIOD=0
ANA_RESULTS_FILE="$ANA_MLC_DIR/ana/results.dat"

ANA_NODE_MAX=$((( $mlc_min_node + $ANA_NODES_MAX - 1 )))
ANA_ATTACK_ROLE_COLORS=(orange rosa cyan)
ANA_CPA_ATTACK_NODE="1009"
ANA_CPA_TRUST_NODES="1002 1007 1152 1157"
ANA_NODE_PROBE_PAIRS="1002:1152 1007:1157 1012:1162 1012:1152 1012:1157"


ANA_ATTACK_OF_DIR="$ANA_MLC_DIR/ana"
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




ana_time_stamp() {
    date +%Y%m%d-%H%M%S
}

ana_update_mlc() {
    ssh root@mlc "cd $ANA_PROT_DIR && \
	make clean_all build_all install EXTRA_CFLAGS='-pg -DPROFILING -DCORE_LIMIT=20000 -DTRAFFIC_DUMP -DCRYPTLIB=POLARSSL_1_3_3'"
}


ana_update_dst() {

    [ "$ANA_DST_SYS" ] &&  scp $ANA_DST_SYS root@$ANA_DST1_IP4:/tmp/
    [ "$ANA_DST_FILES" ] && scp $ANA_DST_FILES root@$ANA_DST1_IP4:/tmp/

#   [ "$ANA_DST_SYS" ] &&  scp $ANA_DST_SYS root@$ANA_DST2_IP4:/tmp/
#   [ "$ANA_DST_FILES" ] && scp $ANA_DST_FILES root@$ANA_DST2_IP4:/tmp/
    
    if [ "$ANA_DST_PACKAGES" ]; then
	ssh root@$ANA_DST1_IP4 rm /tmp/*.ipk
echo    scp $ANA_DST_PACKAGES root@$ANA_DST1_IP4:/tmp/
	scp $ANA_DST_PACKAGES root@$ANA_DST1_IP4:/tmp/
	ssh root@$ANA_DST1_IP4 opkg install /tmp/*.ipk

#	ssh root@$ANA_DST2_IP4 rm /tmp/*.ipk
#	scp $ANA_DST_PACKAGES root@$ANA_DST2_IP4:/tmp/
#	ssh root@$ANA_DST2_IP4 opkg install /tmp/*.ipk
    fi
}

ana_create_nodes() {
    if [ "$(mlc_ls | grep RUNNING | wc -l)" = "$((( $ANA_NODES_MAX + 1 )))" ]; then
	echo "already $ANA_NODES_MAX + 1 nodes RUNNING"
    else
	mlc_loop -a $ANA_NODE_MAX -cb
	mlc_qdisc_prepare
	[ "$(mlc_ls | grep RUNNING | wc -l)" = "$((( $ANA_NODES_MAX + 1 )))" ] || echo "MISSING NODES"
    fi

    # ANA_PROTO_RM:
    rm -f $ANA_MLC_DIR/rootfs/mlc*/rootfs/etc/config/bmx6
    rm -f $ANA_MLC_DIR/rootfs/mlc*/rootfs/usr/lib/bmx6_*


    killall -w iperf
    mlc_loop -a 1009 -e "iperf -Vs > /dev/null 2>&1 &"
    mlc_loop -a $ANA_NODE_MAX -e "echo 10 > /proc/sys/net/ipv6/icmp/ratelimit"

}




ana_create_protos_dst() {

    local nodes=${1:-$ANA_NODES_DEF}

    if [ "$nodes" = "0" ]; then

	$ANA_SSH root@$ANA_DST1_IP4 "while ps |grep -e $ANA_PROTO| grep -v grep; do killall $ANA_PROTO; timeout 0.2 sleep 1d ; done; rm -f $ANA_PROTO_RM"

    else
	$ANA_SSH root@$ANA_DST1_IP4 "$ANA_DST_CMD"
	$ANA_SSH root@$ANA_DST1_IP4 "ip6tables --flush; ip6tables -P FORWARD ACCEPT"
#	$ANA_SSH root@$ANA_DST1_IP4 "ip6tables -I INPUT -i br-lan -s fe80::16cf:92ff:fe52:13a6 -j DROP"

#	$ANA_SSH root@$ANA_DST2_IP4 "$ANA_DST_CMD"
#	$ANA_SSH root@$ANA_DST2_IP4 "ip6tables --flush; ip6tables -P FORWARD ACCEPT"
#	$ANA_SSH root@$ANA_DST2_IP4 "ip6tables -I INPUT -i br-lan -s fe80::16cf:92ff:fe52:f10  -j DROP"
    fi
}

ana_create_protos_mlc() {
    local nodes=${1:-$ANA_NODES_DEF}

    if [ "$nodes" = "0" ]; then
	killall -w $ANA_PROTO

    else

#	[ $nodes -lt $ANA_NODES_MAX ] && \
#	    mlc_loop -i $((( 1000 + $nodes ))) -a $((( 1000 + $ANA_NODES_MAX - 1))) -e "killall -w $ANA_PROTO"

	local bmxPs=$(ps aux | grep "$ANA_MAIN_CMD" | grep -v grep | wc -l)

	[ $nodes -gt $bmxPs ] && \
	    mlc_loop -li $(((1000 + $bmxPs ))) -a $((( 1000 + $nodes - 1))) -e "$ANA_MLC_CMD"

    fi
}

ana_create_protos() {
    local nodes=${1:-$ANA_NODES_DEF}
    ana_create_protos_dst $nodes
    ana_create_protos_mlc $nodes
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

ana_create_keys_owrt() {

    local nodeVersion="$(     ssh root@$ANA_DST1_IP4 "( bmx6 -c version || bmx6 nodeSignatureLen=$ANA_NODE_KEY_LEN /keyPath=/etc/bmx6/rsa.$ANA_NODE_KEY_LEN version ) | grep version=BMX" )"
    local nodeId="$( echo "$nodeVersion" | awk -F'id=' '{print $2}' | cut -d' ' -f1 )"; nodeId=${nodeId:-"-"}
    local nodeName="$( echo "$nodeVersion" | awk -F'hostname=' '{print $2}' | cut -d' ' -f1 )"; nodeName=${nodeName:-"-"}
    echo "nodeVersion=$nodeVersion nodId=$nodeId nodeName=$nodeName"

    ana_create_role_key_dirs $ANA_ATTACK_PEN_LEVEL
    touch $ANA_MLC_KEYS_DIR/orange-trusted-nodes/$nodeId.$nodeName

    ssh root@$ANA_DST1_IP4 "mkdir -p /$ANA_NODE_TRUSTED_DIR; rm -f /$ANA_NODE_TRUSTED_DIR/*"
    scp $ANA_MLC_KEYS_DIR/orange-trusted-nodes/* root@o101:/$ANA_NODE_TRUSTED_DIR/
}

ana_bench_tp_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}

    local dst6=$( $ANA_SSH root@$ANA_E2E_SRC4 "bmx6 -c list=originators"  | grep "name=$ANA_E2E_DST" | awk -F'primaryIp=' '{print $2}' | cut -d' ' -f1 )

#   $ANA_SSH root@$ANA_E2E_SRC4 "traceroute6 -n $dst6"

    local ping=$( $ANA_SSH root@$ANA_E2E_SRC4 "ping6 -nc2 $dst6" | head -n3 | tail -n1 )
    local ttl=$( echo $ping | awk -F'ttl=' '{print $2}' | cut -d' ' -f1 )
    local rtt=$( echo $ping | awk -F'time=' '{print $2}' | cut -d' ' -f1 )
    local tp=$( $ANA_SSH root@$ANA_E2E_SRC4 "iperf -V -t $duration -y C -c $dst6 | cut -d',' -f9" 2>/dev/null )

    echo "dst6=$dst6 ttl=$ttl rtt=$rtt tp=$tp" > $outFile
    cat $outFile
}

ana_bench_top_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}
    local dst4=${3:-$ANA_DST1_IP4}

    echo "ana_bench_top_owrt begin"
    ssh root@$dst4 "top -b -n2 -d $duration" > $outFile.tmp
    local mem=$(cat $outFile.tmp | grep "$ANA_MAIN_CMD" | grep -v "grep" | tail -n1 | awk '{print $5}')
    local cpu=$(cat $outFile.tmp | grep "$ANA_MAIN_CMD" | grep -v "grep" | tail -n1 | awk '{print $7}'| cut -d'%' -f1)
    local idl=$(cat $outFile.tmp | grep "CPU:" | grep -v "grep" | tail -n1 | awk '{print $8}'| cut -d'%' -f1)
    
    echo "mem=$mem cpu=$cpu idl=$idl" > $outFile
    echo "ana_bench_top_owrt end:"
    cat $outFile
}

ana_bench_top_sys() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}

    echo "ana_bench_top_sys begin"
    top -b -n2 -d $duration > $outFile.tmp
    local idl=$(cat $outFile.tmp | grep "^%Cpu" | grep -v "grep" | tail -n1 | awk '{print $8}')
    local mem=$(cat $outFile.tmp | grep "^KiB Mem" | grep -v "grep" | tail -n1 | awk '{print $7}')
    
    echo "mem=$mem idl=$idl" > $outFile
    echo "ana_bench_top_sys end:"
    cat $outFile
}

ana_bench_tcp_owrt() {
    local outFile=$1
    local duration=${2:-$ANA_MEASURE_TIME}

    echo "ana_bench_tcp_owrt begin"
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
    echo "ana_bench_tcp_owrt finished"
}

ana_create_updates() {
    local updDuration=$1
    local updPeriod=$2

    echo "updating descriptions for $updDuration s every $updPeriod s ... ( $(date) )"

    if [ $(printf "%.0f\n" $(echo "$updPeriod * 100" | bc)) -ge 10 ]; then
	local updRounds=$( echo "scale=2; $updDuration / $updPeriod" | bc )
	local r=
	for r in $(seq 0 $updRounds); do
	    sleep $updPeriod &
	    local n=$((( $mlc_min_node + 10 + (r % 30) )))
	    mlc_loop -i $n -e "bmx6 -c descUpdate" 
	    wait
	done
    else
	sleep $updDuration
    fi
    echo "updating descriptions done ( $(date) )"
}


ana_measure_ovhd_owrt() {

    local duration=${1:-$ANA_MEASURE_TIME}
    local updPeriod=${2:-$ANA_UPD_PERIOD}
    local resultsFile=${3:-$ANA_RESULTS_FILE}
    local header=$4

    local start=$(ana_time_stamp)
    mkdir -p $(dirname $resultsFile)

    local tmpDir=$(mktemp -d)

    local bmxStatus="$( ssh root@$ANA_DST1_IP4 "bmx6 -c list=status" )"
    local links="$( echo "$bmxStatus" | awk -F'nbs=' '{print $2}' | cut -d' ' -f1 )"
    local nodes="$( echo "$bmxStatus" | awk -F'nodes=' '{print $2}' | cut -d'/' -f1 )"
    local bmxCpu="$( echo "$bmxStatus" | awk -F'cpu=' '{print $2}' | cut -d' ' -f1 )"
    local txPps="$( echo "$bmxStatus" | awk -F'txBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f2)"
    local txBps="$( echo "$bmxStatus" | awk -F'txBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f1)"
    local rxPps="$( echo "$bmxStatus" | awk -F'rxBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f2)"
    local rxBps="$( echo "$bmxStatus" | awk -F'rxBpP=' '{print $2}' | cut -d' ' -f1 | cut -d '/' -f1)"
    local linkRsa="$( echo "$bmxStatus" | awk -F'linkKey=RSA' '{print $2}' | cut -d' ' -f1 )"
    local nodeRsa="$( echo "$bmxStatus" | awk -F'nodeKey=RSA' '{print $2}' | cut -d' ' -f1 )"
    local txq="$( echo "scale=2; $(echo "$bmxStatus" | awk -F'txQ=' '{print $2}' | cut -d' ' -f1)" | bc) "
    local rev="$( echo "$bmxStatus" | awk -F'revision=' '{print $2}' | cut -d' ' -f1 )"

    ana_create_updates $((( (2 * $duration) + (2 * $ANA_MEASURE_GAP) + 25 ))) $updPeriod &

    sleep $ANA_MEASURE_GAP
    [ $links -ge 3 ] && (
	echo "tp started ( $(date) )"
	ana_bench_top_owrt $tmpDir/cpl.out $duration &
	ana_bench_tp_owrt $tmpDir/tp.out $duration & 
	wait
	echo "tp finished ( $(date) )"
    )

    sleep $ANA_MEASURE_GAP
    true && (
	echo "bench started ( $(date) )"
	ana_bench_top_sys  $tmpDir/ids.out $duration &
	ana_bench_top_owrt $tmpDir/top.out $duration &
	ana_bench_tcp_owrt $tmpDir/tcp.out $duration &
	wait
	echo "bench finished ( $(date) )"
    )

    echo "waiting for finished descUpdates... ( $(date) )"
    wait
    echo "summarizing results.. ( $(date) )"
    local mem=$(cat $tmpDir/top.out | awk -F'mem=' '{print $2}'| cut -d' ' -f1)
    local cpu=$(cat $tmpDir/top.out | awk -F'cpu=' '{print $2}'| cut -d' ' -f1)

    local cpl=$(cat $tmpDir/cpl.out | awk -F'cpu=' '{print $2}'| cut -d' ' -f1)
    local ids=$(cat $tmpDir/ids.out | awk -F'idl=' '{print $2}'| cut -d' ' -f1)
    local idl=$(cat $tmpDir/cpl.out | awk -F'idl=' '{print $2}'| cut -d' ' -f1)
    local tp=$(cat $tmpDir/tp.out | awk -F'tp=' '{print $2}'| cut -d' ' -f1)
    local rtt=$(cat $tmpDir/tp.out | awk -F'rtt=' '{print $2}'| cut -d' ' -f1)
    local ttl=$(cat $tmpDir/tp.out | awk -F'ttl=' '{print $2}'| cut -d' ' -f1)

    local outPps=$(cat $tmpDir/tcp.out | awk -F'txP=' '{print $2}'| cut -d' ' -f1)
    local outBps=$(cat $tmpDir/tcp.out | awk -F'txB=' '{print $2}'| cut -d' ' -f1)
    local inPps=$(cat  $tmpDir/tcp.out | awk -F'rxP=' '{print $2}'| cut -d' ' -f1)
    local inBps=$(cat  $tmpDir/tcp.out | awk -F'rxB=' '{print $2}'| cut -d' ' -f1)

    rm -r $tmpDir
    
    FORMAT="%16s %16s %9s   %6s %6s %4s %4s %4s %4s %4s %6s   %8s %8s %8s %8s   %10s %11s %9s %8s %5s  %10s %6s %3s" 
    FIELDS="start end revision  Links Nodes CPU BCPU CPL IDS IDL Memory   outPps outBps inPps inBps   linkRsa nodeRsa updPeriod duration txq  tp rtt ttl"
    printf "$FORMAT \n" $FIELDS
    [ $header ] && printf "$FORMAT \n" $FIELDS > $resultsFile
    printf "$FORMAT \n" \
	$start $(ana_time_stamp) ${rev:-"NA"} \
	${links:-"NA"} ${nodes:-"NA"} ${cpu:-"NA"} ${bmxCpu:-"NA"} ${cpl:-"NA"} ${ids:-"NA"} ${idl:-"NA"} ${mem:-"NA"} \
	${outPps:-"NA"} ${outBps:-"NA"} ${inPps:-"NA"} ${inBps:-"NA"} \
	${linkRsa:-"NA"} ${nodeRsa:-"NA"} ${updPeriod:-"NA"} ${duration:-"NA"} ${txq:-"NA"} \
	${tp:-"NA"} ${rtt:-"NA"} ${ttl:-"NA"} | tee -a $resultsFile
}



ana_fetch_node_role() {

    local anaId=${1:-$mlc_min_node}
    local penLevel=${2:-$ANA_ATTACK_PEN_LEVEL}

    local anaIp="$(MLC_calc_ip4 $mlc_ip4_admin_prefix1 $anaId $mlc_admin_idx )"
    local nodeName="${mlc_name_prefix}${anaId}"
    local nodeVersion="$( $mlc_ssh root@$anaIp "( bmx6 -c version || bmx6 nodeSignatureLen=$ANA_NODE_KEY_LEN /keyPath=/etc/bmx6/rsa.$ANA_NODE_KEY_LEN version ) | grep version=BMX" )"
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
    local roleFile="$ANA_ATTACK_OF_DIR/$ANA_ATTACK_OF_PREFIX-$penLevel"
    local i=

    mkdir -p $ANA_ATTACK_OF_DIR
    rm -f $roleFile

    for i in $(seq $mlc_min_node $ANA_NODE_MAX); do
	
	local line="$(ana_fetch_node_role $i $penLevel )"
	echo "$line" >> $roleFile 
	printf "%d" $(echo "$line" | awk '{print $13}')

	[ $((( ($i + 1 - $mlc_min_node) % $ANA_ATTACK_TOPO_COLS ))) -eq 0 ] && echo

    done
    echo
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


ana_init_ovhd_scenarios() {

    killall -w $ANA_PROTO

    ./mlc-init-host.sh
    
    ana_create_nodes
    ana_create_net_owrt
    ana_create_links_owrt

    ana_create_protos_mlc 0
    ana_fetch_roles 0
    ana_create_keys_owrt

}

ana_set_protos_owrt() {
    local nodes=${1:-$ANA_NODES_DEF}
    local param="${2:-"date"}"

    ssh root@$ANA_DST1_IP4 "$param"
    mlc_loop -la $((( $mlc_min_node + $nodes - 1 ))) -e "$param"
}

ana_run_ovhd_scenarios() {

#   ana_init_ovhd_scenarios

    local params=
    local p=
    local results=
    local round=

    for round in $(seq 1 10); do

	if true; then
	    params="10 20 30 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180"
	    results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsNodes"
	    ana_create_protos 0
	    ana_create_links_owrt
	    for p in $params; do
		echo "MEASURING to $results p=$p of $params"
		ana_create_protos $p
		sleep $ANA_STABILIZE_TIME
		ana_measure_ovhd_owrt $ANA_MEASURE_TIME $ANA_UPD_PERIOD $results "$(echo $params | grep -q "^$p" && echo withHeader)"
	    done
	fi

	if true; then
	    params="4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"
	    results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsLinks"
	    ana_create_protos 0
	    ana_create_links_owrt 0
	    ana_create_protos
	    for p in $params; do
		echo "MEASURING to $results p=$p of $params"
		ana_create_links_owrt $p
		sleep $ANA_STABILIZE_TIME
		ana_measure_ovhd_owrt $ANA_MEASURE_TIME $ANA_UPD_PERIOD $results "$(echo $params | grep -q "^$p" && echo withHeader)"
	    done
	fi

	if true; then
	    params="10 7 5 3 2 1 0.7 0.5 0.4"
	    params="1 0.7 0.5 0.4"
	    results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsUpdates"
	    ana_create_protos 0
	    ana_create_links_owrt
	    ana_create_protos
	    for p in $params; do
		echo "MEASURING to $results p=$p of $params"
		sleep $ANA_STABILIZE_TIME
		ana_measure_ovhd_owrt $ANA_MEASURE_TIME $p $results "$(echo $params | grep -q "^$p" && echo withHeader)"
	    done
	fi

	if true; then
	    params="512 768 896 1024 1536"
	    results="$(dirname $ANA_RESULTS_FILE)/$(ana_time_stamp)-ovhdVsCrypt"
	    ana_create_protos 0
	    ana_create_links_owrt
	    ana_create_protos
	    for p in $params; do
		echo "MEASURING to $results p=$p of $params"
		ana_set_protos_owrt $ANA_LINKS_DEF "bmx6 -c linkSignatureLen=$p"
		sleep $ANA_STABILIZE_TIME
		ana_measure_ovhd_owrt $ANA_MEASURE_TIME $ANA_UPD_PERIOD $results "$(echo $params | grep -q "^$p" && echo withHeader)"
	    done
	fi


    done
}



ana_enable_trust() {
   local nodeId=${1:-"$ANA_CPA_TRUST_NODES"}
   local id=
   for id in $nodeId; do
       mlc_loop -i $id -e "bmx6 -c trustedNodesDir=/etc/bmx6/trustedNodes"
   done
}

ana_disable_trust() {
   local nodeId=${1:-"$ANA_CPA_TRUST_NODES"}
   local id=
   for id in $nodeId; do
       mlc_loop -i $id -e "bmx6 -c trustedNodesDir=-"
   done
}

ana_enable_cpa_attack() {
   local nodeId=${1:-"$ANA_CPA_ATTACK_NODE"}
   mlc_loop -i $nodeId -e "bmx6 -c evilOgmSqns=1" 
}

ana_disable_cpa_attack() {
   local nodeId=${1:-"$ANA_CPA_ATTACK_NODE"}
   mlc_loop -i $nodeId -e "bmx6 -c evilOgmSqns=-" 
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



ana_fetch_roles() {
    local penLevels=${1:-"$((( $ANA_ATTACK_TOPO_COLS / $ANA_ATTACK_TOPO_ROLES )))"}
    local i=

    for i in $(seq 0 $penLevels); do
	ana_fetch_role $i
    done

}


ana_init_security_scenarios() {

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


ana_run_security_scenarios() {

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

#    ana_init_security_scenarios

    ana_configure_grid $ANA_NODE_MAX $lq $ANA_ATTACK_TOPO_COLS

    for i in $(seq 0 $penLevels); do
	echo ana_run_security_scenarios $lq $i
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