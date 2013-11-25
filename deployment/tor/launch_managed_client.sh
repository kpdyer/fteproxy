#!/bin/sh

sudo pkill -9 -f fteproxy
sudo pkill -9 -f tor

export TOR_PT_STATE_LOCATION=/tmp
export TOR_PT_MANAGED_TRANSPORT_VER=1
export TOR_PT_CLIENT_TRANSPORTS=fte

/usr/local/fteproxy/bin/fteproxy --mode client --managed
