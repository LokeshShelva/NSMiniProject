import json
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

class CustomAlgo:
    def __init__(self, user_id, **kwargs):
        self.user_id = user_id
        self.rsa_key = self.__import_rsa_key()
        self.kwargs = kwargs

    def encrypt(self, payload: str, reciever_key_id: int) -> str:
        encryption_key = self.__generate_aes_key(16)
        rsa_reciever_key = self.__get_reciever_key(reciever_key_id)
        
        header = self.__get_header()
        encoded_header = self.__base64_encode(header.encode('utf-8'))
        
        encrypted_encryption_key = self.__get_encrypted_payload_encryption_key(encryption_key, rsa_reciever_key.public_key())
        encoded_encrypted_encryption_key = self.__base64_encode(encrypted_encryption_key)

        cipher_text, auth_tag, nonce = self.__get_ciphertext_and_auth_tag_with_nonce(encryption_key, payload)
        encoded_cipher_text = self.__base64_encode(cipher_text)
        encoded_auth_tag = self.__base64_encode(auth_tag)
        encoded_nonce = self.__base64_encode(nonce)

        message = ".".join([x.decode('utf-8') for x in (encoded_header, encoded_encrypted_encryption_key, encoded_nonce, encoded_cipher_text, encoded_auth_tag)])

        message_signature = self.__get_message_signature(message)
        encoded_message_signature = self.__base64_encode(message_signature)

        return message + "." + encoded_message_signature.decode('utf-8')


    def decrypt(self, message: str) -> str:
        rsa_sender_key = self.__get_sender_key(1)

        success, encrypted_message = self.__check_message_signature(message, rsa_sender_key)
        
        if not success:
            print("Message signature does not match.")
            return

        encoded_header, encoded_encrypted_encryption_key, encoded_nonce, encoded_cipher_text, encoded_auth_tag = encrypted_message

        header = json.loads(self.__base64_decode(encoded_header).decode('utf-8'))
        
        encrypted_encryption_key = self.__base64_decode(encoded_encrypted_encryption_key)
        cipher_text = self.__base64_decode(encoded_cipher_text)
        auth_tag = self.__base64_decode(encoded_auth_tag)
        nounce = self.__base64_decode(encoded_nonce)

        encryption_key = self.__get_payload_encryption_key(encrypted_encryption_key)
        
        payload = self.__get_payload(encryption_key, cipher_text, nounce, auth_tag)

        if payload == None:
            print("Cipher Text nonce does not match")
            return
        
        return payload.decode('utf-8')

    # Encryption helpers
    def __get_message_signature(self, message):
        message_hash = SHA256.new(message.encode('utf-8'))
        return pkcs1_15.new(self.rsa_key).sign(message_hash)
    
    def __get_ciphertext_and_auth_tag_with_nonce(self, encryption_key, payload):
        aes_encryptor = AES.new(encryption_key, AES.MODE_EAX)
        ciphet_text, auth_tag = aes_encryptor.encrypt_and_digest(payload.encode('utf-8'))
        return [ciphet_text, auth_tag, aes_encryptor.nonce]

    def __get_encrypted_payload_encryption_key(self, encryption_key, rsa_reciever_key):
        rsa_encryptor = PKCS1_OAEP.new(rsa_reciever_key.public_key())
        return rsa_encryptor.encrypt(encryption_key)

    def __get_header(self):
        header = {
            "alg": self.kwargs.get('alg') or "rsa",
            "enc": self.kwargs.get('enc') or "aes128",
            "dig": self.kwargs.get('dig') or "sha256",
            "kid": self.kwargs.get('kid') or 1
        }
        return json.dumps(header)
        
    # Decryption helpers
    def __check_message_signature(self, message, rsa_sender_key):
        encrypted_message, _, encoded_signature = message.rpartition('.')
        recieved_message_signature = self.__base64_decode(encoded_signature)
        calculated_message_hash = SHA256.new(encrypted_message.encode('utf-8'))
        try:
            pkcs1_15.new(rsa_sender_key.public_key()).verify(calculated_message_hash, recieved_message_signature)
            return [True, encrypted_message]
        except:
            return [False, None]

    def __get_payload_encryption_key(self, encrypted_encryption_key):
        rsa_encryptor = PKCS1_OAEP.new(self.rsa_key)
        return rsa_encryptor.decrypt(encrypted_encryption_key)

    def __get_payload(self, encryption_key, cipher_text, nounce, auth_tag):
        aes_encryptor = AES.new(encryption_key, AES.MODE_EAX, nonce=nounce)
        try:
            payload = aes_encryptor.decrypt_and_verify(cipher_text, auth_tag)
            return payload
        except:
            return None
    
    def __import_rsa_key(self):
        encoded_key = open(f"keys/rsa_key{self.user_id}.bin").read()
        rsa_key = RSA.import_key(encoded_key, passphrase=self.kwargs.get('rsa_key_pass'))
        return rsa_key
        
    def __get_reciever_key(self, reciever_id):
        encoded_key = open("keys/rsa_key2.bin").read()
        rsa_key = RSA.import_key(encoded_key, passphrase="password2")
        return rsa_key

    def __get_sender_key(self, sender_id):
        encoded_key = open("keys/rsa_key1.bin").read()
        rsa_key = RSA.import_key(encoded_key, passphrase="password1")
        return rsa_key

    def __generate_aes_key(self, key_size_in_bytes):
        return get_random_bytes(key_size_in_bytes)

    def __base64_encode(self, payload):
        return b64encode(payload)

    def __base64_decode(Self, payload):
        return b64decode(payload)
