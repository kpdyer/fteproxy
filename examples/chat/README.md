# FTE Chat Example

A simple echo client/server using `fteproxy.wrap_socket` for FTE encryption.

## Architecture

```
[Client] --binary (0/1)--> [Server]
[Client] <--letters (A/B)-- [Server]
```

Both directions use different formats to demonstrate FTE's flexibility.

## Usage

1. Start the server:
   ```bash
   python server.py
   ```

2. In another terminal, run the client:
   ```bash
   python client.py
   ```

The client sends "Hello, world" to the server, which echoes it back.
All traffic is FTE-encoded using the specified regular expressions.

## Key Concepts

### Using negotiate=False

This example uses `negotiate=False` in `wrap_socket()`:

```python
sock = fteproxy.wrap_socket(sock,
                            outgoing_regex='^(0|1)+$',
                            outgoing_fixed_slice=256,
                            incoming_regex='^(A|B)+$',
                            incoming_fixed_slice=256,
                            negotiate=False)  # Both sides know the formats
```

When `negotiate=False`:
- Both client and server must specify the same formats
- No negotiation cell is sent
- Useful for symmetric setups where both sides know the protocol

### Format Specifications

| Direction | Regex | Description |
|-----------|-------|-------------|
| Client to Server | `^(0\|1)+$` | Binary digits |
| Server to Client | `^(A\|B)+$` | Letters A and B |

## Notes

- Based on Python's socket documentation examples
- Demonstrates programmatic use of FTE (not relay mode)
- Server echoes all received data back to client
