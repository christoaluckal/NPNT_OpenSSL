# This file contains the C++ codes <br>

1.	`createsign.cpp` : This code uses the openSSL C library to sign and verify a file.
2.	`xml_proc.cpp` : This code uses the pugiXML library to parse the signed XML document to extract relevant information.
3.	`key.cpp` : This code reads the certificate path and extracts the public key and saves it in the intermediate folder `temp`
4.	`testC14N.cpp` : This is a modified version of the `testC14N.c` of libxml2 and is used for canonicalization
5.	`main.cpp` : This is the main driver code 
