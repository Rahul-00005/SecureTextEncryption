# Secure Text Compression and Encryption System (Java)

Requires JDK 17+. Uses only standard Java libraries.

## Run

```sh
javac SecureTextSystem.java
java SecureTextSystem
```

Choose 1, provide `sample.txt`, `sample.enc`, and `sample.key`. To recover, choose 2 and provide `sample.enc`, `recovered.txt`, and `sample.key`.

## Design

- zlib-compatible compression with Deflater, decompression with Inflater.
- AES-256-GCM authenticated encryption, 12-byte random IV, 128-bit tag.
- File format: `STE1` magic (4 bytes) + IV (12 bytes) + ciphertext and tag.
- 32-byte raw AES key stored separately; protect this file and never send it alongside the ciphertext.
- Reports compression and encryption timing and sizes.
- Rejects tampered ciphertext or incorrect keys before decompressing.

## Limitations

This teaching implementation loads complete files into memory and limits decompressed output to 100 MiB. It does not protect key files with a password or operating-system access controls. For sensitive real-world use, use secure key management, atomic writes and streaming I/O. For short text, encryption metadata can outweigh compression savings.
