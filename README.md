```ruby
██████╗  ██████╗ ██╗  ██╗████████╗ ██████╗  ██████╗ ██╗
██╔══██╗██╔════╝ ██║  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
██████╔╝██║  ███╗███████║   ██║   ██║   ██║██║   ██║██║
██╔══██╗██║   ██║╚════██║   ██║   ██║   ██║██║   ██║██║
██████╔╝╚██████╔╝     ██║   ██║   ╚██████╔╝╚██████╔╝███████╗
╚═════╝  ╚═════╝      ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

> Multi-format encoding/decoding CLI with recursive layer detection for security analysis.

## What It Does

- Encode and decode Base64, Base64URL, Base32, Hex, and URL formats
- Auto-detect encoding format with confidence scoring
- Peel command recursively strips multi-layered encoding (WAF bypass analysis)
- Chain multiple encoding steps to test obfuscation patterns
- Pipeline-friendly output for integration into security workflows

## Quick Start

```bash
uv tool install b64tool
b64tool encode "Hello World"
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `b64tool encode` | Encode text into Base64, Base64URL, Base32, Hex, or URL format |
| `b64tool decode` | Decode encoded text back to plaintext |
| `b64tool detect` | Auto-detect the encoding format with confidence scoring |
| `b64tool peel` | Recursively strip multi-layered encoding to reveal original data |
| `b64tool chain` | Chain multiple encoding steps together for obfuscation testing |
