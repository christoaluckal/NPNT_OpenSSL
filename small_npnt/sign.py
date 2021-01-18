import signxml as sx
from lxml import etree
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
import base64
data_to_sign = open('permission.xml').read()
# digest = hashes.Hash(hashes.SHA256())
# digest.update(bytes(str.encode(data_to_sign)))
# print(base64.b64encode(digest.finalize()))
# print(base64.b64encode(sha256(data_to_sign.encode('utf-8')).digest()))
# print(b'NGEzOGI1Yzk3NmZkMWY3MzI5YWVlYjEyMWQ1NTIyMTBhZGYyNWRkN2NmYjM4ZjZjOTI3ZDUwNTA3YTdkYzRiOQ==')
cert = open("dgca.cert").read()
key = open("private.pem").read()
root = etree.fromstring(data_to_sign)
signed_root = sx.XMLSigner()
ns = {}
ns[None] = signed_root.namespaces['ds']
signed_root.namespaces = ns
signed_root = signed_root.sign(root, key=key, cert=cert)
# print(etree.tostring(signed_root,pretty_print=True))
kek = etree.ElementTree(etree.fromstring(etree.tostring(signed_root,method="c14n")))
kek.write("fin_signed.xml")
