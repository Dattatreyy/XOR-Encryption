# XOR-Encryption
simple string decryption using XOR operation in Python

def xor_decrypt(ciphertext, key):
    decrypted_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, key))
    return decrypted_text

# Example usage:
encrypted_string = "YourEncryptedString"
encryption_key = "YourEncryptionKey"

decrypted_result = xor_decrypt(encrypted_string, encryption_key)

print("Encrypted String:", encrypted_string)
print("Decrypted Result:", decrypted_result)


Replace "YourEncryptedString" with the actual encrypted string and "YourEncryptionKey" with the encryption key you used. 
The xor_decrypt function performs the XOR decryption operation.
