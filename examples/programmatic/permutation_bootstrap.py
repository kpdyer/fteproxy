#!/usr/bin/env python3
"""Negotiate client-only regexes and echo bytes over a local socket pair.

Install the checkout first: python -m pip install -e ".[test]"
Run: python examples/programmatic/permutation_bootstrap.py [--mode hybrid]
"""

import argparse
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

import fteproxy


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('peer closed before the complete message')
        data.extend(chunk)
    return bytes(data)


def echo(sock, key, size):
    # No regex, length, definitions release, or data mode is supplied here.
    with fteproxy.wrap_socket(sock, negotiation='permutation', key=key) as server:
        received = read_exact(server, size)
        server.sendall(received)
        return server.parameters


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('format', 'hybrid'), default='format')
    args = parser.parse_args()

    # A real deployment provisions the same secret independently at both ends.
    key = secrets.token_bytes(32)
    client_raw, server_raw = socket.socketpair()
    client_raw.settimeout(5)
    server_raw.settimeout(5)
    payload = b'A regex chosen by the client, learned by the server.\n' * 128
    upstream = r'^(ab[0-9a-f]+cd|ef[0-9a-f]+gh)$'
    downstream = r'^ACK:[A-Z0-9]+!$'

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(echo, server_raw, key, len(payload))
            with fteproxy.wrap_socket(
                client_raw, negotiation='permutation', key=key,
                outgoing_regex=upstream, outgoing_length=256,
                incoming_regex=downstream, incoming_length=256,
                record_layer_mode=args.mode,
            ) as client:
                client.sendall(payload)  # Lazily completes the handshake first.
                if read_exact(client, len(payload)) != payload:
                    raise AssertionError('echo differs from the original message')
            learned = result.result(timeout=10)
    finally:
        client_raw.close()
        server_raw.close()

    print('Permutation bootstrap completed; the server began with only the key.')
    print(f'  Client → server: {learned.upstream_regex} ({learned.upstream_length} bytes)')
    print(f'  Server → client: {learned.downstream_regex} ({learned.downstream_length} bytes)')
    print('  Bootstrap: 320 complete covertexts, 80 KiB')
    print(f'  Echo verified: {len(payload):,} application bytes in {learned.mode} mode')


if __name__ == '__main__':
    main()
