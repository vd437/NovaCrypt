from mycryptlib import encrypt, decrypt, encrypt_file, decrypt_file, generate_secure_key

def main():
    print("NovaCrypt Demonstration")
    
    # Basic string encryption
    message = "Secret message containing sensitive data"
    password = "strong_password_123"
    
    print(f"\nOriginal message: {message}")
    
    encrypted = encrypt(message.encode('utf-8'), password)
    print(f"\nEncrypted data (hex): {encrypted[:64].hex()}... (length: {len(encrypted)} bytes)")
    
    decrypted = decrypt(encrypted, password)
    print(f"\nDecrypted message: {decrypted.decode('utf-8')}")
    
    # File encryption demo
    input_file = "demo_input.txt"
    encrypted_file = "demo_encrypted.ncr"
    decrypted_file = "demo_decrypted.txt"
    
    with open(input_file, 'w') as f:
        f.write("This is a test file for NovaCrypt encryption")
    
    print("\nEncrypting file...")
    encrypt_file(input_file, encrypted_file, password)
    
    print("Decrypting file...")
    decrypt_file(encrypted_file, decrypted_file, password)
    
    with open(decrypted_file, 'r') as f:
        print(f"\nDecrypted file contents: {f.read()}")

if __name__ == '__main__':
    main()