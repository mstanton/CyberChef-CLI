# CyberChef CLI

A command-line implementation of GCHQ's CyberChef, the "Cyber Swiss Army Knife" for data manipulation and analysis.

## Features

- Process data using operations similar to the web version of CyberChef
- Chain multiple operations to create recipes
- Read input from files or stdin
- Output to files or stdout
- Save and load recipes

## Installation

### From crates.io

```bash
cargo install cyberchef-cli
```

### From source

```bash
git clone https://github.com/yourusername/cyberchef-cli
cd cyberchef-cli
cargo build --release
```

The executable will be located at `target/release/cyberchef-cli`.

## Usage

```bash
# Basic operation
cyberchef-cli --op "base64-decode" "SGVsbG8gd29ybGQh"

# Chain multiple operations (recipe)
cyberchef-cli --recipe "base64-decode | to-hex" "SGVsbG8gd29ybGQh"

# Read from file
cyberchef-cli --op "md5" --input-file data.txt

# Write to file
cyberchef-cli --op "aes-encrypt --key 'mysecretkey'" --input-file data.txt --output-file encrypted.bin

# Save recipe
cyberchef-cli --recipe "base64-decode | to-hex" --save-recipe my-recipe.json

# Load and use saved recipe
cyberchef-cli --load-recipe my-recipe.json --input-file data.txt
```

## Available Operations

### Encoding/Decoding
- base64-encode/decode
- url-encode/decode
- hex-encode/decode
- ascii85-encode/decode
- morse-encode/decode
- ... and more

### Encryption/Decryption
- aes-encrypt/decrypt
- des-encrypt/decrypt
- rsa-encrypt/decrypt
- ... and more

### Hashing
- md5
- sha1
- sha256
- sha512
- ... and more

### Compression
- gzip-compress/decompress
- bzip2-compress/decompress
- ... and more

### Data Analysis
- entropy
- file-type
- magic (auto-detect)
- ... and more

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgements

This project is inspired by [CyberChef](https://github.com/gchq/CyberChef), developed by [GCHQ](https://www.gchq.gov.uk/).
