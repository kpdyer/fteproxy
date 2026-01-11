# Programmatic fteproxy Examples

These examples show how to use fteproxy's Python API directly in your applications.

## Examples

### 1. `simple_encoder.py`
Direct encoding/decoding without network sockets. Good for understanding how FTE transforms data.

### 2. `echo_client.py` / `echo_server.py`
Basic echo server using `fteproxy.wrap_socket()`.

### 3. `format_demo.py`
Demonstrates different output formats (words, hex, base64, etc.).

### 4. `custom_format.py`
Shows how to define and use custom regex formats.

### 5. `file_transfer.py`
Simple file transfer example using FTE encoding.

## Running the Examples

```bash
# Install fteproxy first
pip install fteproxy

# Run simple encoder demo
python simple_encoder.py

# Run echo server/client (in separate terminals)
python echo_server.py
python echo_client.py

# See different output formats
python format_demo.py

# Create custom formats
python custom_format.py
```
