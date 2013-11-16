#!/bin/sh

# assumes proxy is running on 127.0.0.1:8081

sudo pkill -9 -f fteproxy
sudo pkill -9 -f tor

export TOR_PT_STATE_LOCATION=/tmp
export TOR_PT_MANAGED_TRANSPORT_VER=1
export TOR_PT_CLIENT_TRANSPORTS=fte
export TOR_PT_EXTENDED_SERVER_PORT=
export TOR_PT_ORPORT=127.0.0.1:8081
export TOR_PT_SERVER_BINDADDR=fte-0.0.0.0:8080
export TOR_PT_SERVER_TRANSPORTS=fte

fteproxy --mode server --managed
