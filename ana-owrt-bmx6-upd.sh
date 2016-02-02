#!/bin/ash

command=$0
period=$1

echo "command=$command period=$period -> $((( -1 * $period )))"

if [ "$period" ]; then
        echo starting...
    while true; do time bmx6 -c descUpdate; sleep $((( -1 * $period))); done &
else
        pcs="$(ps | grep -e $command | grep -v grep | awk '{print $1}')"
        echo "stopping $pcs"
        kill $pcs

fi
