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
# rsa.decrypt("eyJhbGciOiAicnNhIiwgImVuYyI6ICJhZXMiLCAiZGlnIjogIiJ9.FbStas06W7RLugnuy4twvvV84UaQefpVGvZ/BcLabQrgI4CujpHwBqwZkqsUDro2r1C7ab1GrILrkyayPUs9eO/NEx86/rrWWdFbuZ4O52J+wqtdNGD5EwscASznAJkh7Gz7fNT85NVO9xz1VuVKB1Z9NQb0bdQ+fJxrZHndIhIma6Qo33dL09BjAmYyow3X298P/RjUqWpXxo2b1J/xJfa/n+mNI69o3JXabH3MomKNZ5KSx6q/SmJJEAeJKCeYWTElLR4yOVy2IDUt9xf96MPfaEXbZRohwyBH+qH/KuIxwEgd/PNrHWScEir5PbHWMRCj2yWBTgz+FHB3uPheaQ==.uE5A8ICRrsR0Gzil.TgSSPH1OV9vxTdF273jYbA==.MGJjYTcyOThiZTdlZWQ4NzYyZjU5ODJlYjc0MzQxNTE2ZTJmMjA4ZDAyYzI3ZWIzMjMzZDQ3NTM0NjlhYzZiZQ==")
msg = sender.encrypt("Hello World!", 2)

reciever = CustomAlgo(2, rsa_key_pass="password2")
print(reciever.decrypt(msg))