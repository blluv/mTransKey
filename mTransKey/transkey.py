import re
import requests

from . import crypto
from .keypad import KeyPad

from random import randint

keyboardTypes = {
    "qwerty": "qwertyMobile",
    "number": "numberMobile"
}
class mTransKey():
    def __init__(self, sess, servlet_url):
        self.sess: requests.Session = sess
        self.servlet_url = servlet_url
        self.crypto = crypto.Crypto()
        self.token = ""
        self.qwerty = []
        self.number = []
        
        self._get_token()
        self._get_key_data()
    
    def _get_token(self):
        txt = self.sess.get("{}?op=getToken".format(self.servlet_url)).text
        self.token = re.findall("var TK_requestToken=(.*);", txt)[0]

    def _get_key_data(self):
        key_data = self.sess.post(self.servlet_url, data={
            "op": "setSessionKey",
            "key": self.crypto.get_encrypted_key(),
            "transkeyUuid": self.crypto.uuid,
            "useCert": "true",
            "TK_requestToken": self.token,
            "mode": "Mobile"
        }).text

        qwerty, num = key_data.split("var numberMobile = new Array();")
        
        qwerty_keys = []
        number_keys = []
        
        for p in qwerty.split("qwertyMobile.push(key);")[:-1]:
            points = re.findall("key\.addPoint\((\d+), (\d+)\);", p)
            qwerty_keys.append(points[0])

        for p in num.split("numberMobile.push(key);")[:-1]:
            points = re.findall("key\.addPoint\((\d+), (\d+)\);", p)
            number_keys.append(points[0])

        self.qwerty = qwerty_keys
        self.number = number_keys

    def new_keypad(self, key_type, name, inputName, fieldType = "password"):
        skip_data = self.sess.post(self.servlet_url, data={
            "op": "allocation",
            "name": name,
            "keyType": "",
            "keyboardType": keyboardTypes[key_type],
            "fieldType": fieldType,
            "inputName": inputName,
            "transkeyUuid": self.crypto.uuid,
            "TK_requestToken": self.token,
            "dummy": "undefined",
            "talkBack": "true"
        }).text

        skip = list(map(int, skip_data.split(",")))

        if key_type == "qwerty":
            return KeyPad(self.crypto, key_type, skip, self.qwerty)
        else:
            return KeyPad(self.crypto, key_type, skip, self.number)
    
    def hmac_digest(self, message):
        return self.crypto.hmac_digest(message)

    def get_uuid(self):
        return self.crypto.uuid
