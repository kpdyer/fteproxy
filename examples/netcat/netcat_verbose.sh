#!/bin/sh

# the IP:port our fteproxy client listens on
CLIENT_IP=127.0.0.1
CLIENT_PORT=8079

# the IP:port our fteproxy server listens on
SERVER_IP=127.0.0.1
SERVER_PORT=8080

# the IP:port where our fteproxy forwards all connections
# in this test, it's the IP:port the server-side netcat will bind to
PROXY_IP=127.0.0.1
PROXY_PORT=8081

# start fteproxy client
./bin/fteproxy --mode client --quiet \
               --client_ip $CLIENT_IP --client_port $CLIENT_PORT \
               --server_ip $SERVER_IP --server_port $SERVER_PORT & 

# start fteproxy server
./bin/fteproxy --mode server --quiet \
               --server_ip $SERVER_IP --server_port $SERVER_PORT \
               --proxy_ip $PROXY_IP --proxy_port $PROXY_PORT &

# start server-side netcat listener
netcat -k -l -p $PROXY_PORT

# start client-side netcat pusher in another window
# nc $CLIENT_IP $CLIENT_PORT
