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
  a.  Make sure that the script has proper permissions. <br>
5. You can also build using cmake as follows <br>
  a.	Go to the root directory and use `mkdir build && cd build` <br>
  b.	`cmake ..` <br>
  c.	`make` <br>
  d.	This will create the main executable file called as main. Simply execute the main executable with `./main ../xmls/fin_signed.xml` or replace the second argument with any signed XML whose validity is being tested. <br>
  
To verify if checking works, change a value in the permission tag in the `xmls/fin_signed.xml` file

## How it works ##
0. Read the info at https://www.w3.org/TR/xmldsig-core1/ to understand the basic idea.
1. In step 1 of the above mentioned Method, we use the base `permission.xml` to generate a signed version called as `fin_signed.xml`
2. When the main script is executed, it compiles and executes the C++ codes in the `cpp` folder. <br>
   a. The first step creates a folder called as `temp` in the `cpp` directory. This folder as its name suggests, temporarily holds the files for the verification process. The folder and its contents are deleted once the program is executed irrespective of the outcome. <br>
   b. During the verification process, the `fin_signed.xml` is not in the required format. Hence, we parse this XML and convert it into the desired format. From the formatted XML file, we extract the canonicalized version of the `SignedInfo` and the `Permission` tag content. We also extract the base64 encoded X509 certificate credentials. <br>
   c. Once the desired data is extracted from the XML, we extract the public key from the X509 certificate. This public key is used for the signature verification process. <br>
   d. We now hash the canonicalized `Permission` tag content saved in the file `temp/c14n_pugi_PI.xml` and save the hash into a string. We also extract the hash value stored in the `DigestValue` of the signed XML in `fin_signed.xml`. The hash of the `DigestValue` in the `temp/c14n_pugi_SI.xml` is replaced with the calculated hash (**NOT THE EXTRACTED ONE**). If the file has not been tampered with, the calculated hash will be the same as the extracted hash. `temp/c14n_pugi_SI.xml` is once again canonicalized into `temp/c14n_c14n_pugi_SI.xml` to ensure formatting accuracy. <br>
   e. Now we have the public key extracted in step c, the data that is signed i.e. `temp/c14n_c14n_pugi_SI.xml` and an empty buffer which is the size of the final signature. If the signed XML file has not been tampered with, the output should be a success. <br>
   f. The basic principle of the verification process is that, if the `Permission` tag content is altered, the calculated hash will also be altered. When this altered hash is added into the `temp/c14n_pugi_SI.xml` and subsequently into the canonicalized version `temp/c14n_c14n_pugi_SI.xml`, the signature verification will fail.
