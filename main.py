def generate_key(code):
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    encrypted_key = key.export_key(passphrase=code, pkcs=8, protection="scryptAndAES128-CBC")

    file_out = open("rsa_key2.bin", "wb")
    file_out.write(encrypted_key)
    file_out.close()

    file_out = open("rsa_key2_pub.bin", "wb")
    file_out.write(key.publickey().export_key())
    file_out.close()

from CustomAlgo import CustomAlgo

sender = CustomAlgo(1, rsa_key_pass="password1")
msg = sender.encrypt("abcd", 2)
reciever = CustomAlgo(2, rsa_key_pass="password2")
print(reciever.decrypt(msg))