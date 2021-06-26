import requests
from mTransKey.transkey import mTransKey

ID = ""
PW = ""

sess = requests.session()
mtk = mTransKey(sess, "https://m.cultureland.co.kr/transkeyServlet")

pw_pad = mtk.new_keypad("qwerty", "passwd", "passwd", "password")

encrypted = pw_pad.encrypt_password(PW)
hm = mtk.hmac_digest(encrypted.encode())

k = sess.post("https://m.cultureland.co.kr/mmb/loginProcess.do", data={
    "agentUrl": "",
    "returnUrl": "",
    "keepLoginInfo": "",
    "phoneForiOS": "",
    "hidWebType": "other",
    "userId": ID,
    "passwd": "*"*len(PW),
    "transkeyUuid": mtk.get_uuid(),
    "transkey_passwd": encrypted,
    "transkey_HM_passwd": hm
})

print(k.text)