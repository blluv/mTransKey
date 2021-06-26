import os
import hmac
import hashlib

from . import seed

from Crypto.Hash import SHA1
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import construct


def get_rsa_key():
    n = int("00e5140260e76b7e635e50815cc8c4f097f8db1b7bc0cd8bd41ea3d59921cf1b14404e1eadf295ec6f77d208966d5db7ad7127f8f21e59b1cd280b4ac7b448634341dbefe5ede898b0b19480331c1fc53e87a08a6af209d5765bc232bd9d3978eb8f2b0f8646aefc59ca33e83e9bf73dbfc600ab9fdc8983ba3e3f32d41f7c863f5944df6873ff89326259fa8931623086d9b33734ea2182482dd3bf21668a8f83abeb53b0b597f24a6627940dcd1de0d94e37662db4077e6b4f3f0f588b795fdee650bce945a50038abfd4f339962506995b17ab73e9ea36160e52237b28ab4697f56eb21b500b30c0b06d7b4c01aa7597b5c098beeb90eb7124256982bad9133", 16)
    e = int("010001", 16)
    rsa_key = construct((n, e))

    return rsa_key

class Crypto():
    def __init__(self):
        self.uuid = os.urandom(int(32)).hex()
        self.genSessionKey = os.urandom(int(8)).hex()
        self.sessionKey = [int(i, 16) for i in list(self.genSessionKey)]
        
    def _pad(self, txt):
        if len(txt) < 16:
            txt += b'\x00'*(16 - len(txt))
        return txt

    def get_encrypted_key(self):
        cipher = PKCS1_OAEP.new(key=get_rsa_key(), hashAlgo=SHA1)
        return cipher.encrypt(self.genSessionKey.encode()).hex()

    def hmac_digest(self, msg: bytes):
        return hmac.new(
            msg=msg,
            key=self.genSessionKey.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
    
    def seed_encrypt(self, iv, data):
        s = seed.SEED()
        round_key = s.SeedRoundKey(bytes(self.sessionKey))
        return s.my_cbc_encrypt(self._pad(data), round_key, iv)