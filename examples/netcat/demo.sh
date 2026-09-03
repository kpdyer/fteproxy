#!/bin/bash
#
# FTE Proxy Netcat Demo
#
# Demonstrates fteproxy by tunneling netcat traffic through FTE encoding.
# Run this script, then in another terminal: echo "Hello" | nc 127.0.0.1 8079
#

set -e

# Configuration
CLIENT_PORT=8079
SERVER_PORT=8080
DEST_PORT=8081

# A throwaway state directory, so the demo neither reads nor writes the server
# key you use for real. The server generates a keypair in here on startup and
# writes the connection string to connection.txt; the client reads it back
# from the same place, so neither side needs the string on its command line.
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fteproxy-demo.XXXXXX")"

# Track background PIDs for cleanup
PIDS=()

cleanup() {
    trap - EXIT INT TERM
    echo ""
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$STATE_DIR"
    exit 0
}

trap cleanup EXIT INT TERM

# Wait until $2 shows up in the log file $1, or until the process $3 dies.
wait_for() {
    local logfile="$1" pattern="$2" pid="$3" i
    for i in $(seq 1 120); do
        grep -q "$pattern" "$logfile" 2>/dev/null && return 0
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    echo "Failed to start. Log follows:"
    sed 's/^/    /' "$logfile"
    return 1
}

echo "================================================================"
echo "                   FTE Proxy Netcat Demo                        "
echo "================================================================"
echo ""
echo "Traffic flow:"
echo ""
echo "  [You] -> :$CLIENT_PORT -> [FTE Client] -> [FTE Server] -> :$DEST_PORT -> [nc]"
echo "           plaintext       FTE encoded       plaintext"
echo ""
echo "================================================================"
echo ""

# Start fteproxy server. --allow is what lets it dial the netcat listener:
# with no rule at all it refuses its own loopback addresses.
echo "[1/3] Starting FTE server (listening on :$SERVER_PORT, may dial 127.0.0.1:$DEST_PORT)..."
python3 -m fteproxy server \
    --state-dir "$STATE_DIR" \
    --listen "127.0.0.1:$SERVER_PORT" \
    --advertise "127.0.0.1:$SERVER_PORT" \
    --allow "127.0.0.1:$DEST_PORT" \
    > "$STATE_DIR/server.log" 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)
wait_for "$STATE_DIR/server.log" 'clients connect with' "$SERVER_PID"

# Start fteproxy client. -L picks the destination -- the server has no forward
# address of its own -- and the destination travels inside the tunnel.
echo "[2/3] Starting FTE client (forwarding :$CLIENT_PORT to 127.0.0.1:$DEST_PORT through the tunnel)..."
python3 -m fteproxy client \
    --state-dir "$STATE_DIR" \
    -L "$CLIENT_PORT:127.0.0.1:$DEST_PORT" \
    > "$STATE_DIR/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=($CLIENT_PID)
wait_for "$STATE_DIR/client.log" 'forwarding' "$CLIENT_PID"
sed 's/^/      /' "$STATE_DIR/client.log"

# Start netcat listener
echo "[3/3] Starting netcat listener on :$DEST_PORT..."
echo ""
echo "================================================================"
echo "Ready! In another terminal, run:"
echo ""
echo "    echo 'Hello, FTE!' | nc 127.0.0.1 $CLIENT_PORT"
echo ""
echo "You should see the message appear below."
echo "Press Ctrl+C to stop."
echo "================================================================"
echo ""

# The listener runs in the background and the script waits on it, so that a
# Ctrl+C reaches the cleanup trap instead of being swallowed by a foreground nc.
# -k keeps it listening after the first connection; not every nc has it.
nc -l -k "$DEST_PORT" 2>/dev/null &
NC_PID=$!
sleep 0.5
if ! kill -0 "$NC_PID" 2>/dev/null; then
    nc -l "$DEST_PORT" &
    NC_PID=$!
fi
PIDS+=($NC_PID)
wait "$NC_PID" || true
