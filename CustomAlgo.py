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
        self.kwargs = kwargs

    def encrypt(self, payload: str, reciever_id: int) -> str:
        encryption_key = self.__generate_aes_key(16)
        rsa_key = self.__import_rsa_key()
        rsa_reciever_key = self.__get_reciever_key(reciever_id)
        
        header = self.__create_header()
        encoded_header = self.__base64_encode(header.encode('utf-8'))
        
        rsa_encryptor = PKCS1_OAEP.new(rsa_reciever_key.public_key())
        encrypted_encryption_key = rsa_encryptor.encrypt(encryption_key)
        encoded_encrypted_encryption_key = self.__base64_encode(encrypted_encryption_key)

        aes_encryptor = AES.new(encryption_key, AES.MODE_EAX) # !TODO: Change the mode to include IV
        cipher_text, auth_tag = aes_encryptor.encrypt_and_digest(payload.encode('utf-8'))
        encoded_cipher_text = self.__base64_encode(cipher_text)
        encoded_auth_tag = self.__base64_encode(auth_tag)
        
        nonce = aes_encryptor.nonce
        encoded_nonce = self.__base64_encode(nonce)

        message = ".".join([x.decode('utf-8') for x in (encoded_header, encoded_encrypted_encryption_key, encoded_nonce, encoded_cipher_text, encoded_auth_tag)])

        message_hash = SHA256.new(message.encode('utf-8'))
        message_signature = pkcs1_15.new(rsa_key).sign(message_hash)
        encoded_message_signature = self.__base64_encode(message_signature)

        return message + "." + encoded_message_signature.decode('utf-8')


    def decrypt(self, message: str) -> str:
        rsa_key = self.__import_rsa_key()
        rsa_sender_key = self.__get_sender_key(1)

        split_list = message.split(".")
        message = ".".join(split_list[:-1])
        encoded_header, encoded_encrypted_encryption_key, encoded_nonce, encoded_cipher_text, encoded_auth_tag, encoded_message_signature = split_list
        
        recieved_message_signature = self.__base64_decode(encoded_message_signature)
        calculated_message_hash = SHA256.new(message.encode('utf-8'))

        try:
            pkcs1_15.new(rsa_sender_key.public_key()).verify(calculated_message_hash, recieved_message_signature)
        except:
            print("Message Signature does not match.")
            return 

        header = json.loads(self.__base64_decode(encoded_header).decode('utf-8'))
        encrypted_encryption_key = self.__base64_decode(encoded_encrypted_encryption_key)
        cipher_text = self.__base64_decode(encoded_cipher_text)
        auth_tag = self.__base64_decode(encoded_auth_tag)
        nounce = self.__base64_decode(encoded_nonce)

        rsa_encryptor = PKCS1_OAEP.new(rsa_key)
        encryption_key = rsa_encryptor.decrypt(encrypted_encryption_key)
        
        aes_encryptor = AES.new(encryption_key, AES.MODE_EAX, nonce=nounce)
        payload = aes_encryptor.decrypt_and_verify(cipher_text, auth_tag)
        
        return payload.decode('utf-8')
        
    def __create_header(self):
        header = {
            "alg": self.kwargs.get('alg') or "rsa",
            "enc": self.kwargs.get('enc') or "aes",
            "dig": self.kwargs.get('dig') or "", # !TODO: What algo to use
            "kid": 1
        }
        return json.dumps(header)
        
    def __import_rsa_key(self):
        encoded_key = open(f"keys/rsa_key{self.user_id}.bin").read()
        rsa_key = RSA.import_key(encoded_key, passphrase=self.kwargs.get('rsa_key_pass'))
        return rsa_key
        
    #!TODO: Make this function dynamic
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
