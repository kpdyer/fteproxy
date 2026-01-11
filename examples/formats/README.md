# FTE Output Format Examples

This directory contains shell scripts that demonstrate different output formats.
Each format makes your traffic look like different types of data.

## Available Formats

| Format | Description | Example Output |
|--------|-------------|----------------|
| `lowercase` | Random lowercase letters | `xkcdpqmwrtyghasdf...` |
| `uppercase` | Random UPPERCASE letters | `XKCDPQMWRTYGHASDF...` |
| `words` | Space-separated words | `hello world foo bar...` |
| `hex` | Hexadecimal string | `a1b2c3d4e5f6...` |
| `digits` | Numeric digits | `8675309420...` |
| `base64` | Base64-like characters | `aGVsbG8gd29ybGQ...` |
| `binary` | Binary (0s and 1s) | `01101000011001...` |

## Usage

Each script starts a server-client pair using a specific format:

```bash
# Terminal 1 - Start server
./words_server.sh

# Terminal 2 - Start client  
./words_client.sh
```

Then connect to port 8079 to send data through the FTE tunnel.

## Why Different Formats?

Different formats help evade different types of traffic analysis:

- **HTTP-like**: Mimics web traffic
- **Words**: Appears as natural text
- **Hex/Base64**: Looks like encoded data (common in APIs)
- **Digits**: Could pass as numeric data
