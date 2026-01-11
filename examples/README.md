# fteproxy Examples

A comprehensive collection of examples demonstrating fteproxy's capabilities.

## What is fteproxy?

fteproxy transforms your network traffic to look like something else.

```
[Your App] --> [fteproxy client] ==> [fteproxy server] --> [destination]
               (encodes traffic)     (decodes traffic)

Traffic between client and server looks like:
- random words
- HTTP requests
- SSH banners
- hex strings
- anything you want!
```

## Directory Structure

```
examples/
|
|-- basic/                  Getting started
|   |-- README.md
|   |-- start_server.sh     Start a server
|   +-- start_client.sh     Start a client
|
|-- chat/                   Echo server demo
|   |-- README.md
|   |-- server.py           FTE-wrapped echo server
|   +-- client.py           FTE-wrapped echo client
|
|-- formats/                Output format demos
|   |-- README.md
|   |-- comparison_demo.py  Compare all formats side-by-side
|   |-- words_demo.py       Traffic as English-like words
|   +-- http_demo.py        Traffic as HTTP requests
|
|-- programmatic/           Python API examples
|   |-- README.md
|   |-- simple_encoder.py   Direct encoding (no sockets)
|   |-- echo_server.py      Socket wrapper server
|   |-- echo_client.py      Socket wrapper client
|   |-- format_demo.py      All formats demonstration
|   |-- custom_format.py    Create your own formats
|   +-- file_transfer.py    Send files over FTE
|
|-- integration/            Tool integration
|   |-- README.md
|   |-- ssh_tunnel.sh       SSH over FTE
|   |-- web_proxy.sh        Web browsing over FTE
|   +-- secure_chat.py      Encrypted chat app
|
+-- netcat/                 Quick demo
    |-- README.md
    +-- demo.sh             One-command demo
```

---

## Basic Examples

**Location:** `basic/`

The simplest way to get started with fteproxy.

### start_server.sh

Starts an fteproxy server that:
- Listens for FTE-encoded connections on port 8080
- Forwards decoded traffic to port 8081

```bash
./start_server.sh
```

### start_client.sh

Starts an fteproxy client that:
- Listens for plaintext on port 8079
- Sends FTE-encoded traffic to the server

```bash
./start_client.sh [server-ip]
```

### Try it out

```bash
# Terminal 1: Start server
./start_server.sh

# Terminal 2: Start a service (e.g., netcat)
nc -l 8081

# Terminal 3: Start client
./start_client.sh

# Terminal 4: Send data
echo "Hello through FTE!" | nc localhost 8079
```

---

## Chat Examples

**Location:** `chat/`

A simple echo server/client demonstrating `fteproxy.wrap_socket()`.

### How it works

```python
import socket
import fteproxy

# Create a regular socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap it with FTE encoding
sock = fteproxy.wrap_socket(sock,
    outgoing_regex="^[a-z]+$",      # Send as lowercase letters
    outgoing_fixed_slice=256,
    incoming_regex="^[A-Z]+$",      # Receive as UPPERCASE
    incoming_fixed_slice=256,
    negotiate=False)

# Use normally - encoding is transparent!
sock.connect(("localhost", 50007))
sock.sendall(b"Hello!")
```

### Try it out

```bash
# Terminal 1
python3 server.py

# Terminal 2
python3 client.py
```

---

## Format Examples

**Location:** `formats/`

See how the same data looks when encoded with different formats.

### comparison_demo.py

Shows all formats side-by-side:

```bash
python3 comparison_demo.py
```

Output:
```
Secret message: Hello, World!

Format       | Sample Output                                          
----------------------------------------------------------------------
Lowercase    | cgkotttxwgupqyhdtosnixzyooehpzlgzejthseolfvlkrwcjksxquz
Uppercase    | CKOOJBEQIDKHJKTZFJSBNJASAQLYUSQHLWXZVAYJEXYQCQJYUFUQKFE
Digits       | 0231945802172231145855818304822631859446838418075470674
Hex          | 00af2703420aa54af5d8eb6214085183553156b9761d9acb6d2d334
Words        | aamfyleiuih umiepyivwfxjnwqwnedqswfq ztpualumddmayzbziz
Binary       | 0000000010111000100101111011110111011100000111111101001
```

### words_demo.py

Encodes traffic as space-separated words:

```bash
python3 words_demo.py
```

Your "Secret message" becomes: `hello world foo bar qux baz...`

### http_demo.py

Encodes traffic to look like HTTP:

```bash
python3 http_demo.py
```

Your "Secret message" becomes: `GET /a8Kj2mNp HTTP/1.1\r\n\r\n`

---

## Programmatic Examples

**Location:** `programmatic/`

Learn the Python API with these examples.

### simple_encoder.py

Direct FTE encoding without network sockets. Perfect for understanding the basics:

```python
import fte

encoder = fte.Encoder("^[a-z]+$", 256)
ciphertext = encoder.encode(b"Secret!")
plaintext, _ = encoder.decode(ciphertext)
```

```bash
python3 simple_encoder.py
```

### echo_server.py / echo_client.py

Complete client-server example using `fteproxy.wrap_socket()`:

```bash
# Terminal 1
python3 echo_server.py

# Terminal 2
python3 echo_client.py
```

### format_demo.py

Comprehensive demonstration of all available formats:

```bash
python3 format_demo.py
```

### custom_format.py

Learn to create your own regex formats:

```bash
python3 custom_format.py
```

Shows how to make traffic look like:
- Domain names (`example.com`)
- Email addresses (`user@host.com`)
- Key-value pairs (`key=value`)
- HTTP requests (`GET /path HTTP/1.1`)
- Timestamps (`12:34:56`)

### file_transfer.py

Transfer files over FTE encoding:

```bash
# Terminal 1: Receive
python3 file_transfer.py receive

# Terminal 2: Send
python3 file_transfer.py send myfile.txt
```

---

## Integration Examples

**Location:** `integration/`

Use fteproxy with real-world tools.

### ssh_tunnel.sh

Tunnel SSH through FTE so it looks like random text:

```bash
# On server (where sshd is running)
./ssh_tunnel.sh server

# On client
./ssh_tunnel.sh client server-ip

# Then connect normally
ssh -p 8079 user@localhost
```

### web_proxy.sh

Tunnel web traffic through FTE:

```bash
# On server (with a proxy like tinyproxy on port 8888)
./web_proxy.sh server

# On client
./web_proxy.sh client server-ip

# Use with curl
curl -x http://localhost:8079 https://example.com
```

### secure_chat.py

A simple encrypted chat application:

```bash
# Terminal 1
python3 secure_chat.py server

# Terminal 2
python3 secure_chat.py client 127.0.0.1

# Start chatting!
```

---

## Netcat Demo

**Location:** `netcat/`

One-command demo to see fteproxy in action.

### demo.sh

```bash
./demo.sh
```

This starts:
1. FTE server (port 8080)
2. FTE client (port 8079)  
3. Netcat listener (port 8081)

Then in another terminal:
```bash
echo "Hello, FTE!" | nc localhost 8079
```

Traffic flow:
```
You --> :8079 --> [FTE encode] --> :8080 --> [FTE decode] --> :8081 --> netcat
```

---

## Available Formats

fteproxy includes these built-in formats:

| Format | Output Looks Like | Example |
|--------|------------------|---------|
| `lowercase` | Random letters | `xkwqprmstyz` |
| `uppercase` | CAPITAL LETTERS | `XKWQPRMSTYZ` |
| `words` | English-like text | `hello world foo` |
| `sentences` | Sentences with periods | `Hello world.` |
| `digits` | Numbers | `8675309420` |
| `hex` | Hexadecimal | `a1b2c3d4e5f6` |
| `base64` | Base64 characters | `SGVsbG8gV29ybGQ` |
| `binary` | Binary (0s and 1s) | `01101000011001` |
| `csv` | Comma-separated | `foo,bar,baz` |
| `ip-address` | IP addresses | `192.168.1.1` |
| `domain` | Domain names | `example.com` |
| `email-simple` | Email addresses | `user@host.com` |
| `url-path` | URL paths | `/api/v1/users` |
| `http-simple` | HTTP requests | `GET /page HTTP/1.1` |
| `ssh` | SSH banners | `SSH-2.0-OpenSSH` |
| `smtp` | SMTP commands | `EHLO mail.com` |
| `ftp` | FTP responses | `220 ftp.com ready` |
| `tls-sni` | TLS SNI style | `www.example.com` |

---

## Use Cases

1. **Bypass Traffic Filtering** - Make your traffic look like allowed protocols
2. **Privacy** - Prevent traffic analysis by disguising patterns  
3. **Testing** - Validate firewall rules and network policies
4. **Research** - Experiment with traffic transformation techniques

---

## More Information

- **Main Documentation:** [README.md](../README.md)
- **Homepage:** https://github.com/kpdyer/fteproxy
- **Paper:** [Protocol Misidentification Made Easy with FTE](https://kpdyer.com/publications/ccs2013-fte.pdf)
