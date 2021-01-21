# This is the XML data that is to be signed <br>

1.	`permission.xml` : Base XML document that is being signed. <br>
## These are generated if you follow the main method <br>
## key: C14N = Canonicalized <br>
1.	`b64txt.sha256` : Binary form generated from the `signature.txt` file using openSSL commands
2.	`binsign.sha256` : Binary signature generated during signing process using openSSL commands
3.	`c14n_PI.xml` : C14N form of `permission.xml`.  **Has no a newline at end**. Generated from `xml_proc.cpp`
4.	`c14n_SI.xml` : C14N form of SignedInfo.  **Has no a newline at end**.  Generated from `xml_proc.cpp`
5.	`fin_signed.xml` : Signed XML document that is used by `xml_proc.cpp`. Generated from `sign.py` using signXML
6.	`permission.xml` : Base XML document that is being signed.
7.	`pugi_PI.xml` : Base form of `permission.xml`. Generated from `xml_proc.cpp`
8.	`pugi_SI.xml` : Base form of SignedInfo. Generated from `xml_proc.cpp`
9.	`signature.txt` : Copied from the stdout when running the `xml_proc.cpp` command
