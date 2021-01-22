#include <iostream>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <assert.h>
#include <iomanip>
using namespace std;
RSA* createPrivateRSA(std::string key);
RSA* createPublicRSA(std::string key);
bool RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc);
bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic);
void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text);
size_t calcDecodeLength(const char* b64input);
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);
char* signMessage(std::string privateKey, std::string plainText);
bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64);
std::string getFileBinaryHashb64(std::string fileName);
std::string readFile(std::string location);
std::string readSignedInfo(std::string location);