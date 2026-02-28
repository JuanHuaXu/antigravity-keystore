import unittest
import os
import shutil
import tempfile
from keystore import initialize_keystore, save_data, load_data, load_key, Fernet

class TestKeystore(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.key_file = os.path.join(self.test_dir, ".test.key")
        self.data_file = os.path.join(self.test_dir, ".test.data")

    def tearDown(self):
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)

    def test_init_and_load(self):
        """Test that the keystore can be initialized and the key loaded."""
        initialize_keystore(self.key_file, self.data_file)
        self.assertTrue(os.path.exists(self.key_file))
        self.assertTrue(os.path.exists(self.data_file))
        
        key = load_key(self.key_file)
        self.assertIsNotNone(key)
        self.assertIsInstance(key, bytes)

    def test_set_and_get_secret(self):
        """Test inserting and retrieving a secret."""
        initialize_keystore(self.key_file, self.data_file)
        key = load_key(self.key_file)
        
        # Initial data should be empty
        data = load_data(key, self.data_file)
        self.assertEqual(data, {})
        
        # Set a secret
        test_key = "DB_PASSWORD"
        test_val = "secure_pass_123"
        data[test_key] = test_val
        save_data(data, key, self.data_file)
        
        # Retrieve it back
        new_data = load_data(key, self.data_file)
        self.assertIn(test_key, new_data)
        self.assertEqual(new_data[test_key], test_val)

    def test_multiple_secrets(self):
        """Test handling multiple secrets."""
        initialize_keystore(self.key_file, self.data_file)
        key = load_key(self.key_file)
        
        secrets = {
            "KEY1": "VAL1",
            "KEY2": "VAL2",
            "KEY3": "VAL3"
        }
        
        save_data(secrets, key, self.data_file)
        
        loaded_secrets = load_data(key, self.data_file)
        self.assertEqual(loaded_secrets, secrets)

    def test_encryption_works(self):
        """Verify that the data file is actually encrypted and not plain text."""
        initialize_keystore(self.key_file, self.data_file)
        key = load_key(self.key_file)
        
        test_val = "sensitive_information"
        save_data({"secret": test_val}, key, self.data_file)
        
        with open(self.data_file, "rb") as f:
            raw_content = f.read()
        
        # The raw content should not contain the plain text secret
        self.assertNotIn(test_val.encode(), raw_content)

if __name__ == "__main__":
    unittest.main()
