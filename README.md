# Antigravity PQC Keystore

A high-security, local encrypted keystore designed for AI agents.

## Security Features
*   **Quantum Resistant (PQC):** AES-256-GCM authenticated encryption.
*   **Brute-Force Shield:** PBKDF2-HMAC-SHA512 key derivation (2M iterations).
*   **Disk-Safe Handshakes:** Uses Bash process substitution (`<(...)`) for SSH key injection to ensure private keys never touch the physical disk.
*   **Atomic Writes:** Protects against data corruption during OS crashes.
*   **OS-Level Hardening:** Files created with `0o600` masks (user-only access).

## Cryptographic Design Choices

### Why AES-256-GCM?
Selected as the primary cipher for its industry-standard status, official FIPS-compliance, and widespread hardware acceleration support.
*   **Hardware Acceleration:** Most modern CPUs utilize **AES-NI** (silicon-level instructions) which makes AES significantly faster and more energy-efficient than software-only ciphers like ChaCha20.
*   **Quantum Resistance:** Grover's algorithm necessitates larger bit-lengths for symmetric encryption. By utilizing its full **256-bit** capacity, our implementation maintains a post-quantum security level of 128-bits.
*   **Authenticated Encryption (AEAD):** GCM mode provides both confidentiality and integrity, ensuring that any tampering with the encrypted database is detected immediately upon decryption attempt.

### AES-256-GCM vs ChaCha20-Poly1305
While ChaCha20 is a robust alternative (often faster on mobile or low-end IoT hardware without AES-NI), we utilize AES for deskop-grade performance and its decades-long standing against cryptographic research/attacks. Our implementation prioritizes **Key Derivation Cost** (2,000,000 PBKDF2 iterations) over cipher speed, as the former is the primary defense against modern GPU-based brute-force attacks.

## License
MIT License
