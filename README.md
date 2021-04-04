# NPNT_OpenSSL
NPNT Compliance using OpenSSL CMD/CXX API

## Prerequisites ##
1. LibXML (libxml2) at ftp://xmlsoft.org/libxml2/

## Follow the method to verify signature <br>
Method
1.  `cd pys/` <br>
  **a.  CD into the python scripts**
2. `python3 sign.py` <br>
  a.  Execute the `sign.py` script which will create `fin_signed.xml` in `xmls/` directory. **This is performed only once**
3.  `cd ..` <br>
  **a.  CD into the main directory**
4. `./check_signature.sh` <br>
  a.  Make sure that the script has proper permissions.

To verify if checking works, change a value in the permission tag in the `xmls/fin_signed.xml` file

## How it works ##
1. In step 1 of Method, we use the base `permission.xml` to generate a signed version called as `fin_signed.xml`
2. When the shell script is executed, it compiles and executes the C++ codes in the `cpp` folder. <br>
   a. The first step creates a folder called as `temp` in the `cpp` directory. This folder as its name suggests, temporarily holds the files for the verification process. <br>
   b. During the verification process, the `fin_signed.xml` is not in the required format. Hence, we parse this XML and convert it into the desired format. From the formatted file we extract the canonicalized version of the `SignedInfo` and the `Permission` XML tag content. We also extract the base64 encoded X509 certificate credentials. <br>
   c. Once the desired data is extracted from the XML, we first extract the public key from the X509 certificate. This public key is used for the signature verification process. We now hash the canonicalized `Permission` tag content saved in the file `temp/c14n_pugi_SI.xml` and save the hash into a string. We also extract the hash value stored in the `DigestValue` of the signed XML.
