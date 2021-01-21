# from Crypto.PublicKey import RSA
from base64 import b64encode

msg = b'<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform><Transform Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod><DigestValue>KE9Qun3M55ddVpgBvzIR6pokli1X2BWFipOnItzx9iw=</DigestValue></Reference></SignedInfo>'
# print(msg)
# key = RSA.importKey(open("private.pem", "rb"))
# print(key.sign(msg,key))

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

key = RSA.import_key(open('private.pem').read())
h = SHA256.new(msg)
signature = pkcs1_15.new(key).sign(h)

print(b64encode(signature))