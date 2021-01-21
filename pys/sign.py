import signxml as sx
from lxml import etree
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
import base64
data_to_sign = open('../xmls/permission.xml').read()
cert = open("../keys/dgca.cert").read()
key = open("../keys/private.pem").read()
root = etree.fromstring(data_to_sign)
signed_root = sx.XMLSigner()
ns = {}
ns[None] = signed_root.namespaces['ds']
signed_root.namespaces = ns
signed_root = signed_root.sign(root, key=key, cert=cert)
# print(etree.tostring(signed_root,pretty_print=True))
kek = etree.ElementTree(etree.fromstring(etree.tostring(signed_root,method="c14n")))
kek.write("../xmls/fin_signed.xml")
