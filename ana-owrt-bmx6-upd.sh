#!/bin/ash

command=$0
period=$1

echo "command=$0 period=$1"

if [ "$period" ]; then
        echo starting...
    while true; do time bmx6 -c descUpdate; sleep $period; done &
else
        pcs="$(ps | grep -e $command | grep -v grep | awk '{print $1}')"
        echo "stopping $pcs"
        kill $pcs

fi
