import unittest
import os
from mycryptlib.core import encrypt, decrypt, encrypt_file, decrypt_file
from mycryptlib.utils import CryptoUtils

class TestNovaCrypt(unittest.TestCase):
    def setUp(self):
        self.test_key = "test_password_123"
        self.test_data = b"Test data to encrypt 12345 !@#$%"
        self.test_file = "test_file.txt"
        self.enc_file = "test_encrypted.ncr"
        self.dec_file = "test_decrypted.txt"
        
        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)
    
    def tearDown(self):
        for f in [self.test_file, self.enc_file, self.dec_file]:
            if os.path.exists(f):
                os.remove(f)
    
    def test_encrypt_decrypt(self):
        encrypted = encrypt(self.test_data, self.test_key)
        decrypted = decrypt(encrypted, self.test_key)
        self.assertEqual(decrypted, self.test_data)
    
    def test_file_encryption(self):
        encrypt_file(self.test_file, self.enc_file, self.test_key)
        decrypt_file(self.enc_file, self.dec_file, self.test_key)
        
        with open(self.dec_file, 'rb') as f:
            decrypted = f.read()
        
        self.assertEqual(decrypted, self.test_data)
    
    def test_tamper_detection(self):
        encrypted = encrypt(self.test_data, self.test_key)
        tampered = encrypted[:40] + bytes([encrypted[40] ^ 0x01]) + encrypted[41:]
        
        with self.assertRaises(ValueError):
            decrypt(tampered, self.test_key)
    
    def test_key_generation(self):
        utils = CryptoUtils()
        key = utils.generate_secure_key(b"test", 32)
        self.assertEqual(len(key), 32)
        self.assertTrue(utils.validate_key_strength(key))

if __name__ == '__main__':
    unittest.main()