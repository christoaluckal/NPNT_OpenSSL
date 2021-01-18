# NPNT_OpenSSL
NPNT Compliance using OpenSSL CMD/CXX API


Method
1.  Run sign.py which generates fin_signed.xml
2.  Copy the `C14N SignedInfo:` terminal entry and write it to codec14n.xml (SignXML signs `<SignedInfo xmlns='...'>` but writes `<SignedInfo>`)
3.  Copy the `<SignatureValue>` from fin_signed.xml to signature.txt
4.  To use the OpenSSL C++ API, use `g++ createsign.cpp -lcrypto` and run the executable. <br>
  a.  This API reads `private.pem` and `public.pem` keys, signs the`codec14n.xml`file and verifies the signature generated using the API and the signature copied to `signature.txt`
5.  To use the `openssl` commands.<br>
  a.  Run `cat codec14n.xml | tr -d '\n' | openssl dgst -sha256 -sign private.pem -out binsign.sha256` <br>
  b.  To verify the SignXML signature: `openssl base64 -d -in signature.txt -out binsign.sha256` (Convert txt file to binary) <br>
  c.  `cat codec14n.xml | tr -d '\n' | openssl dgst -sha256 -verify public.pem -signature binsign.sha256`
