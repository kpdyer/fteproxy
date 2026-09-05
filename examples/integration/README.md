# Integration examples

The client chooses destinations with `-L` or SOCKS5 `-D`; the server applies
`--allow` before dialing. Install fteproxy on both machines first.

## SSH

On the server, replace `vpn.example.com` with its reachable hostname. Run sshd
on port 22, then start fteproxy:

```bash
python3 -m fteproxy server --advertise vpn.example.com:8080 --allow 127.0.0.1:22
```

The server reports the path to `connection.txt`. Copy that file privately to
the client, then run:

```bash
python3 -m fteproxy client --connection-file ./connection.txt -L 2222:127.0.0.1:22
```

In another client terminal:

```bash
ssh -p 2222 user@127.0.0.1
```

The destination `127.0.0.1:22` means the server's loopback address. SSH still
provides its own authentication and encryption through the FTE tunnel.

## SOCKS5 browsing

On the server:

```bash
python3 -m fteproxy server --advertise vpn.example.com:8080
```

Copy its `connection.txt` privately. On the client:

```bash
python3 -m fteproxy client --connection-file ./connection.txt -D 1080
```

Use it from another terminal:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

For a browser, select SOCKS5 at `127.0.0.1:1080` and enable proxy DNS resolution.
This sends destination names through the tunnel for the server to resolve; it
does not proxy every application or UDP traffic.

With no allow rules, the server permits global unicast destinations.
`--allow any` has the same address restriction. To reach a private or loopback
service, add an explicit IP or CIDR rule. Once rules are supplied, unmatched
destinations are denied. See [destination policy](../../README.md#destination-policy).

## Netcat transfer

On the receiving host, start a server allowing `127.0.0.1:9999`, with its reachable
`--advertise` endpoint. In another terminal, receive into a new file:

```bash
nc -l 9999 > received_file.txt
```

On the sender, use the copied connection file:

```bash
python3 -m fteproxy client --connection-file ./connection.txt -L 8079:127.0.0.1:9999
```

In another terminal:

```bash
nc 127.0.0.1 8079 < myfile.txt
```

Netcat variants differ in how they close after stdin EOF; use your version's
EOF option if needed. Compare the received file before treating the transfer
as complete. For automatic local setup, see the [netcat demo](../netcat/README.md).

## Helper scripts and chat

Run the shell helpers from `examples/integration` with no arguments to see
usage. `ssh_tunnel.sh` wraps the SSH setup on port 2222; `web_proxy.sh` wraps
SOCKS5 browsing. Their client wrappers accept a URI argument, which can be
visible in command history and process listings. The commands above use files.
To give the helpers a remote endpoint, provision it first with
`fteproxy keygen --advertise HOST:8080`; the server preserves that endpoint.

For an interactive Python socket demo, run these in separate terminals:

```bash
python3 secure_chat.py server
```

```bash
python3 secure_chat.py client 127.0.0.1
```

It uses HTTP hybrid mode on port 50009 with a published demo key. The server
binds all IPv4 interfaces, and text reads do not preserve message boundaries.
See [demo identities](../README.md#demo-identities) before running it.
