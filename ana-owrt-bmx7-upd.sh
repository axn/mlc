#!/bin/ash

command=$0
period=$1


if [ "$period" ]; then
    echo "starting command=$command period=$period -> $((( -1 * $period )))"
    while true; do time bmx7 -c descUpdate; sleep $((( -1 * $period))); done &
else
    echo "stopping $command"
    killall $command
#    pcs="$(ps | grep -e $command | grep -v grep | awk '{print $1}')"
#    echo "stopping $pcs"
#    kill $pcs
fi
