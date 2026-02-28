import os
import json
import base64
import argparse
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Absolute path to the keystore directory (this file's directory)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, ".keystore.data")
SALT_FILE = os.path.join(BASE_DIR, ".keystore.salt")
KEYSTORE_ENV_FILE = os.path.join(BASE_DIR, ".keystore.env")
ITERATIONS = 2_000_000

def derive_key(password, salt):
    """Derives a 256-bit key from the password and salt using PBKDF2-HMAC-SHA512."""
    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def initialize_keystore():
    """Generates a new salt and saves it, then creates an empty data file."""
    if os.path.exists(SALT_FILE) or os.path.exists(KEYSTORE_ENV_FILE):
        print("Error: Keystore already initialized.")
        return
    
    pw_env = os.getenv("KEYSTORE_PASSWORD")
    if pw_env:
        password = pw_env
    else:
        password = getpass.getpass("Create a Master Password (or press Enter for auto-generated 257-bit): ")
        if not password:
            password = os.urandom(33).hex() # 264 bits > 257
            print(f"Using auto-generated 257-bit (hex) password.")
        else:
            confirm = getpass.getpass("Confirm Master Password: ")
            if password != confirm:
                print("Error: Passwords do not match.")
                return

    # 241 bits -> 31 bytes
    salt = os.urandom(31).hex() 
    
    # Securely save to .keystore.env
    env_content = f"PASSWORD={password}\nSALT={salt}\n".encode()
    fd = os.open(KEYSTORE_ENV_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(env_content)
    
    key = derive_key(password, salt)
    save_data({}, key)
    print("Keystore initialized with AES-256-GCM and PBKDF2-HMAC-SHA512.")


def save_data(data, key):
    """Encrypts and safely saves data using atomic writes and secure file permissions."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    serialized_data = json.dumps(data).encode()
    # AES-256-GCM uses the key directly (256-bit key = Quantum resistant)
    encrypted_data = aesgcm.encrypt(nonce, serialized_data, None)
    
    # Atomic write pattern: Write to .tmp securely, then os.replace
    tmp_file = DATA_FILE + ".tmp"
    fd = os.open(tmp_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(nonce + encrypted_data)
        
    os.replace(tmp_file, DATA_FILE)


def load_data(key):
    """Decrypts data from DATA_FILE using AES-256-GCM."""
    if not os.path.exists(DATA_FILE):
        return {}
    
    with open(DATA_FILE, "rb") as f:
        content = f.read()
    
    if len(content) < 12:
        return {}
    
    nonce = content[:12]
    encrypted_data = content[12:]
    
    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Error: Decryption failed. Incorrect password? ({e})")
        sys.exit(1)

def get_master_password():
    """Gets the master password from environment or .keystore.env."""
    pw = os.getenv("KEYSTORE_PASSWORD")
    if not pw:
        if os.path.exists(KEYSTORE_ENV_FILE):
            with open(KEYSTORE_ENV_FILE, "r") as f:
                for line in f:
                    if line.startswith("PASSWORD="):
                        pw = line.split("=", 1)[1]
                        # Remove trailing newline ONLY, preserving intentional trailing spaces in password
                        if pw.endswith('\n'):
                            pw = pw[:-1]
                        return pw

        pw = getpass.getpass("Enter Master Password: ")
    return pw

def get_salt():
    if os.path.exists(KEYSTORE_ENV_FILE):
        with open(KEYSTORE_ENV_FILE, "r") as f:
            for line in f:
                if line.startswith("SALT="):
                    return line.split("=", 1)[1].strip()
    if not os.path.exists(SALT_FILE):
        return None
    with open(SALT_FILE, "rb") as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser(description="Antigravity Keystore CLI (AES-256-GCM + PQC KDF)")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize the keystore")
    
    set_parser = subparsers.add_parser("set", help="Set a secret")
    set_parser.add_argument("key", help="The secret key")
    set_parser.add_argument("value", help="The secret value")

    get_parser = subparsers.add_parser("get", help="Get a secret")
    get_parser.add_argument("key", help="The secret key")

    subparsers.add_parser("list", help="List all secret keys")

    delete_parser = subparsers.add_parser("delete", help="Delete a secret key")
    delete_parser.add_argument("key", help="The secret key")

    args = parser.parse_args()

    if args.command == "init":
        initialize_keystore()
        return

    salt = get_salt()
    if not salt:
        print("Error: Keystore not initialized. Use 'init' first.")
        sys.exit(1)

    password = get_master_password()
    key = derive_key(password, salt)

    if args.command == "set":
        data = load_data(key)
        data[args.key] = args.value
        save_data(data, key)
        print(f"Secret '{args.key}' set successfully.")

    elif args.command == "get":
        data = load_data(key)
        if args.key in data:
            print(data[args.key])
        else:
            print(f"Error: Secret '{args.key}' not found.")
            sys.exit(1)

    elif args.command == "list":
        data = load_data(key)
        if not data:
            print("No secrets stored.")
        else:
            for k in data.keys():
                print(k)

    elif args.command == "delete":
        data = load_data(key)
        if args.key in data:
            del data[args.key]
            save_data(data, key)
            print(f"Secret '{args.key}' deleted.")
        else:
            print(f"Error: Secret '{args.key}' not found.")
            sys.exit(1)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
