#!/bin/sh

# start fteproxy client
python -m fteproxy --quiet &

# start fteproxy server
python -m fteproxy --mode server --quiet &

# start server-side netcat listener
netcat -k -l -p 8081

# start client-side netcat pusher in another window
# nc localhost 8079
