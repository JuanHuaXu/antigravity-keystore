# Antigravity PQC Keystore

A high-security, local encrypted keystore designed for AI agents.

## Security Features
*   **Quantum Resistant (PQC):** AES-256-GCM authenticated encryption.
*   **Brute-Force Shield:** PBKDF2-HMAC-SHA512 key derivation (2M iterations).
*   **Disk-Safe Handshakes:** Uses Bash process substitution (`<(...)`) for SSH key injection to ensure private keys never touch the physical disk.
*   **Atomic Writes:** Protects against data corruption during OS crashes.
*   **OS-Level Hardening:** Files created with `0o600` masks (user-only access).

## License
MIT License
