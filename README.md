# NPNT_OpenSSL
NPNT Compliance using OpenSSL CMD/CXX API

## Follow the method to generate the proper files <br>
Method
1.  `cd pys/` <br>
  **a.  CD into the python scripts**
2. `python3 pys/sign.py` <br>
  a.  Execute the `sign.py` script which will create `fin_signed.xml` in `xmls/` directory
3.  `cd ../cpp` <br>
  **a.  CD into the CPP directory**
4. `g++ xml_proc.cpp ../pugi/pugixml.cpp` <br>
  a.  Execute the XML Processing Code which will read `xmls/fin_signed.xml`
5. `./a.out` <br>
  a. Copy the base64 encoded Signature Value from terminal and save to `xmls/signature.txt` <br>
  b. `../xmls/c14n_SI.xml` for first input <br>
  c. `../xmls/c14n_PI.xml` for second input <br>
  d.  We now have 4 new files in `xmls/` called as `pugi_PI.xml`,`pugi_SI.xml`,`c14n_SI.xml`,`c14n_PI.xml` and 1 new file in `keys/` called as `pugi_certificate.pem`
6.  `openssl x509 -pubkey -noout -in ../keys/pugi_certificate.pem  > ../keys/pugi_gen_public.pem` <br>
  a.  This extracts the public key from the certificate which will be used for verification purposes
7. `g++ createsign.cpp -lcrypto` <br>
  a.  Execute the openSSL API code which reads `keys/private.pem`,`keys/pugi_gen_public.pem`,`xmls/signature.txt` and `xmls/c14n_SI.xml` <br>
8. `./a.out` <br>
  a.  Sign `c14n_SI.xml` using the `keys/private.pem` and output the base64 encoded signature <br>
  b.  Verify 2 signatures and output the verification result. The first signature is generated from the signing method and the second signature is obtained from the `xmls/signature.txt` file
9. `cd ../xmls` <br>
  **a.  CD into the XML directory**
10. `openssl dgst -sha256 -sign ../keys/private.pem -out binsign.sha256 c14n_SI.xml` <br>
  a.  Sign the `c14n_SI.xml` file using the private key and output the binary `binsign.sha256`
11. `openssl base64 -d -in signature.txt -out b64txt.sha256` <br>
  a.  Read the `signature.txt` file and convert it into the binary `b64txt.sha256`
12. `openssl dgst -sha256 -verify ../keys/pugi_gen_public.pem -signature b64txt.sha256 c14n_SI.xml` <br>
  a.  Verify the converted binary signature with the extracted public key and unsigned `c14n_SI.xml`.

