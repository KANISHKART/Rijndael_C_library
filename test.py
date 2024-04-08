import unittest
import ctypes
import aes.aes as aes


 
# importing .so file after building AES in C using makefile
c_aes = ctypes.CDLL('./rijndael.so')

#  In this code the usage of ctypes.c_ubyte is to make it type safe and allowing ctypes to manage memory automatically

#  1. ctypes.c_ubyte - represents 'unsigned char' in c
#  2. ctypes.POINTER(ctypes.c_ubyte) - represents a pointer to an unsigned char in C. 
#  3. As in C 'aes_encrypt_block' expects pointer to unsigned char array we are doing the step 2
#  4. we are doing this step to prepare arguments when calling the 'aes_encrypt_block' from this code.

#  referred from - https://docs.python.org/3/library/ctypes.html#ctypes.c_ubyte

# the below line sets the args type for the aes_encrypt_block function
c_aes.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.expand_key.argtypes=[ctypes.POINTER(ctypes.c_ubyte)]
c_aes.sub_bytes.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_int]

# the below line sets the response type for the aes_encrypt_block function
c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.sub_bytes.restype= ctypes.c_voidp

class TestEncrypt(unittest.TestCase):
    
    def test_key_matrices(self):
    
        key= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        
        key_arr = (ctypes.c_ubyte * len(key))(*key)
        
        key_matrices_c= c_aes.expand_key(key_arr)
        
        c_bytes = bytes(key_matrices_c[:16]) 
        
        converted_c_bytes=aes.bytes2matrix(c_bytes)
        
        key_matrices_python=(aes.AES(key)._key_matrices)[0]
        
        self.assertEqual(converted_c_bytes,key_matrices_python)
        
    def test_sub_bytes(self):
    
        plaintext_c= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        plaintext_py= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        
        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)
        
        subByte_matrices_c= c_aes.sub_bytes(plaintext_arr, 16)
        
        subByte_matrices_py=aes.sub_bytes(aes.bytes2matrix(plaintext_py))
        
        self.assertEqual(list(plaintext_c),list(plaintext_py))
        
    def test_fail_sub_bytes(self):
    
        plaintext_c= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x12\x33\x11\x04\x08\x06\x63'
        plaintext_py= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        
        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)
        
        subByte_matrices_c= c_aes.sub_bytes(plaintext_arr, 16)
        
        subByte_matrices_py=aes.sub_bytes(aes.bytes2matrix(plaintext_py))
        
        self.assertNotEqual(list(plaintext_c),list(plaintext_py))
        

    def test_c_aes_encrypt_block(self):
        
        plaintext= b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        
        key= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        
        # Converting plaintext & key into ctypes arrays
        plaintext_arr = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        key_arr = (ctypes.c_ubyte * len(key))(*key)

        # Calling the AES encrypt function in main.c
        encrypted_data = c_aes.aes_encrypt_block(plaintext_arr, key_arr)
        
        # Converting the encrypted data back to byte
        c_encrypted_bytes = bytes(encrypted_data[:16]) 
        
        py_encrypted_bytes=aes.AES(key).encrypt_block(plaintext)

        self.assertEqual(c_encrypted_bytes, py_encrypted_bytes)
        
    def test_c_aes_decrypt_block(self):
        
        plaintext= b'\x4b\x95\x86\x93\xb4\xe9\xc4\xeb\x92\xaf\xe8t\xb1\x40\xe0\xce'
        
        key= b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        
        # Converting plaintext & key into ctypes arrays
        plaintext_arr = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        key_arr = (ctypes.c_ubyte * len(key))(*key)

        # Calling the AES decrypt function in main.c
        decrypted_data = c_aes.aes_decrypt_block(plaintext_arr, key_arr)

        # Converting the decrypted data back to byte
        c_decrypted_bytes = bytes(decrypted_data[:16]) 
        
        py_decrypted_bytes=aes.AES(key).decrypt_block(plaintext)

        self.assertEqual(c_decrypted_bytes, py_decrypted_bytes)
        
if __name__ == '__main__':
    unittest.main()