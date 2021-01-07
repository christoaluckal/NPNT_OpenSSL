#include<iostream>
using namespace std;

// Signing
// openssl dgst -sha256 -sign private.pem -out binsign.sha256 perm.txt

// Creating signature txt in base64
// openssl base64 -in binsign.sha256 -out signature.txt

// Converting base64 signature to binary
// openssl base64 -d -in signature.txt -out bin.sha256

// Verifying
// openssl dgst -sha256 -verify publickey.pem -signature bin.sha256 perm.txt


int main(){
    // Read base64 encode signature     // Convert b64 to bin
    std::string command1 = "openssl base64 -d -in signature.txt -out bin.sha256";
    system(command1.c_str());
    // Verify signature with some data
    std::string command2 = "openssl dgst -sha256 -verify publickey.pem -signature bin.sha256 perm.txt";
    system(command2.c_str());

    return 0;
}