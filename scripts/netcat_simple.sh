#!/bin/sh

# start fteproxy client
./bin/fteproxy --quiet &

# start fteproxy server
./bin/fteproxy --mode server --quiet &

# start server-side netcat listener
netcat -k -l -p 8081

# start client-side netcat pusher in another window
# nc $CLIENT_IP $CLIENT_PORT
