#!/bin/bash

# Start WireGuard
wg-quick up wg0-server

# Keep the container running
tail -f /dev/null

# Keep the container running
exec "$@"
