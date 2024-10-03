#!/bin/bash

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Start WireGuard
wg-quick up wg0-server

# Keep the container running
tail -f /dev/null

# Keep the container running
exec "$@"
