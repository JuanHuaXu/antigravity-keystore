import unittest
import os
import shutil
import tempfile
import getpass
import hashlib
from unittest.mock import patch
import keystore

class TestKeystorePQ(unittest.TestCase):
    def setUp(self):
        # Prevent keystore's argparse from interfering with unittest args
        self.patcher = patch('sys.argv', ['test_keystore.py'])
        self.patcher.start()
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.test_dir, ".test.env")
        self.data_file = os.path.join(self.test_dir, ".test.data")
        self.salt_file = os.path.join(self.test_dir, ".test.salt")
        
        # Override the global file paths in the keystore module for testing
        keystore.KEYSTORE_ENV_FILE = self.env_file
        keystore.DATA_FILE = self.data_file
        keystore.SALT_FILE = self.salt_file
        
        # Completely bypass PBKDF2 for tests to prevent hanging, but maintain uniqueness
        self.original_derive_key = keystore.derive_key
        def fast_derive_key(pwd, salt):
            salt_bytes = salt.encode() if isinstance(salt, str) else salt
            return hashlib.sha256(pwd.encode() + salt_bytes).digest()
        keystore.derive_key = fast_derive_key
        
        self.test_password = "test_master_password_123 " # Include trailing space for parsing test
        # Speed up tests by reducing iterations (this line is now effectively bypassed by patching derive_key)
        self.original_getpass = getpass.getpass
        getpass.getpass = lambda prompt="": self.test_password.rstrip()

        # Force KEYSTORE_PASSWORD into the environment so getpass is NEVER called
        os.environ["KEYSTORE_PASSWORD"] = self.test_password.rstrip()
        
    def tearDown(self):
        # Restore getpass (if we kept the mock)
        if hasattr(self, 'original_getpass'):
            getpass.getpass = self.original_getpass
        # Restore derive_key
        keystore.derive_key = self.original_derive_key
        
        self.patcher.stop()
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
        # Clean up global env var
        if "KEYSTORE_PASSWORD" in os.environ:
            del os.environ["KEYSTORE_PASSWORD"]

    def test_init_and_derive(self):
        """Test that the keystore can be initialized with a password."""
        keystore.initialize_keystore()
        
        self.assertTrue(os.path.exists(self.env_file))
        self.assertTrue(os.path.exists(self.data_file))
        
        salt = keystore.get_salt()
        self.assertIsNotNone(salt)
        
        # Verify we can derive the same key
        key1 = keystore.derive_key(self.test_password.rstrip(), salt)
        key2 = keystore.derive_key(self.test_password.rstrip(), salt)
        self.assertEqual(key1, key2)

    def test_set_and_get_with_password(self):
        """Test full cycle: init -> set -> get using the master password."""
        # 1. Init
        keystore.initialize_keystore()
        
        # 2. Set (Provide password for get_master_password)
        with patch.dict(os.environ, {"KEYSTORE_PASSWORD": self.test_password.rstrip()}):
            salt = keystore.get_salt()
            key = keystore.derive_key(self.test_password.rstrip(), salt)
            
            test_key = "CLOUD_AUTH_TOKEN"
            test_val = "quantum-safe-token-value"
            
            data = keystore.load_data(key)
            data[test_key] = test_val
            keystore.save_data(data, key)
            
            # 3. Get
            new_data = keystore.load_data(key)
            self.assertEqual(new_data[test_key], test_val)

    def test_wrong_password_fails(self):
        """Verify that a different password results in decryption failure."""
        # 1. Init
        keystore.initialize_keystore()
        
        salt = keystore.get_salt()
        key = keystore.derive_key(self.test_password.rstrip(), salt)
        
        # Save real data so the file isn't empty, otherwise load_data returns {} early
        keystore.save_data({"secret": "data"}, key)
        
        # 2. Derive key with DIFFERENT password
        wrong_password = "wrong_password_456"
        wrong_key = keystore.derive_key(wrong_password, salt)
        
        # 3. Attempt to load (should trigger sys.exit or error since GCM tag won't match)
        with self.assertRaises(SystemExit):
            keystore.load_data(wrong_key)

    def test_encryption_integrity(self):
        """Check that data is actually encrypted and tag protects integrity."""
        # Setup using env var
        keystore.initialize_keystore()
        
        salt = keystore.get_salt()
        key = keystore.derive_key(self.test_password.rstrip(), salt)
        
        test_val = "secret_payload"
        keystore.save_data({"x": test_val}, key)
        
        with open(self.data_file, "rb") as f:
            raw = f.read()
            
        self.assertNotIn(test_val.encode(), raw)
        
        # Tamper with the ciphertext (GCM should detect this)
        tampered_raw = bytearray(raw)
        tampered_raw[-1] ^= 0xFF # Flip one bit in the tag
        with open(self.data_file, "wb") as f:
            f.write(tampered_raw)
            
        with self.assertRaises(SystemExit):
            keystore.load_data(key)

    def test_atomic_write_safety(self):
        """Verify that a failed write doesn't corrupt the existing data."""
        # 1. Init and write initial data
        keystore.initialize_keystore()
        
        salt = keystore.get_salt()
        key = keystore.derive_key(self.test_password.rstrip(), salt)
        
        initial_data = {"stable_key": "stable_val"}
        keystore.save_data(initial_data, key)
        
        # 2. Simulate a crash during save by mocking os.replace to raise an exception
        crashing_data = {"stable_key": "stable_val", "new_key": "new_val"}
        
        with patch('os.replace', side_effect=OSError("Disk full or crash")):
            try:
                keystore.save_data(crashing_data, key)
            except OSError:
                pass # Expected crash
                
        # 3. Verify original data is untouched
        loaded_data = keystore.load_data(key)
        self.assertEqual(loaded_data, initial_data)
        
        # 4. Cleanup the .tmp file that was left behind
        os.remove(self.data_file + ".tmp")

if __name__ == "__main__":
    unittest.main()
