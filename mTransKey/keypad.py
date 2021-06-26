from . import chars
from random import randint

class KeyPad():
    def __init__(self, crypto, key_type, skip_data, keys):
        self.crypto = crypto
        self.key_type = key_type
        self.skip_data = skip_data
        self.keys = keys

        self.lower = self._calc_skipped_chars(chars.lower)
        self.upper = self._calc_skipped_chars(chars.upper)
        self.special = self._calc_skipped_chars(chars.special)

    def _calc_skipped_chars(self, _chars):
        keyidx = 0
        out = []
        for i in range(len(_chars)+len(self.skip_data)):
            if i in self.skip_data:
                out.append("")
            else:
                out.append(_chars[keyidx])
                keyidx += 1
        return out

    def get_geo(self, message):
        geos = []
        curr = []
        ctype = ""

        for val in list(message):
            if val.isnumeric() or val.islower():
                curr = self.lower
                ctype = "l"

            elif val.isupper():
                curr = self.upper
                ctype = "u"

            else:
                curr = self.special
                ctype = "s"
                
            geos.append((ctype,)+self.keys[curr.index(val)])
        return geos

    def geos_encrypt(self, geos):
        out = ""
        for geo in geos:
            type, x, y = geo

            typechar = ord(type)
            xbytes = bytes(map(int, list(x)))
            ybytes = bytes(map(int, list(y)))
            randnum = randint(0, 100)

            if self.key_type == "qwerty":
                data = b"%c %b %b e%c" % (typechar, xbytes, ybytes, randnum)
            else:
                data = b"%b %b e%c" % (xbytes, ybytes, randnum)
                
            iv = bytes([0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72,
                        0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30])

            out += "$"+self.crypto.seed_encrypt(iv, data).hex(",")
        return out
    
    def encrypt_password(self, pw):
        geos = self.get_geo(pw)
        return self.geos_encrypt(geos)