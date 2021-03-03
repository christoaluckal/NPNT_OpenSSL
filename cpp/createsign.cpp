// https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59
// include -lssl -lcrypto, include string header and replace _cleanup with _free
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

// RSA* createPrivateRSA(std::string key) {
//   RSA *rsa = NULL;
//   const char* c_string = key.c_str();
//   BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
//   if (keybio==NULL) {
//       return 0;
//   }
//   rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
//   return rsa;
// }

RSA* createPublicRSA(std::string key) {
  RSA *rsa = NULL;
  BIO *keybio;
  const char* c_string = key.c_str();
  keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  return rsa;
}

// bool RSASign( RSA* rsa,
//               const unsigned char* Msg,
//               size_t MsgLen,
//               unsigned char** EncMsg,
//               size_t* MsgLenEnc) {
//   EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
//   EVP_PKEY* priKey  = EVP_PKEY_new();
//   EVP_PKEY_assign_RSA(priKey, rsa);
//   if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
//       return false;
//   }
//   if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
//       return false;
//   }
//   if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
//       return false;
//   }
//   *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
//   if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
//       return false;
//   }
//   EVP_MD_CTX_free(m_RSASignCtx);
//   return true;
// }

bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return false;
  }
}

// void Base64Encode( const unsigned char* buffer,
//                    size_t length,
//                    char** base64Text) {
//   BIO *bio, *b64;
//   BUF_MEM *bufferPtr;

//   b64 = BIO_new(BIO_f_base64());
//   bio = BIO_new(BIO_s_mem());
//   bio = BIO_push(b64, bio);

//   BIO_write(bio, buffer, length);
//   BIO_flush(bio);
//   BIO_get_mem_ptr(bio, &bufferPtr);
//   BIO_set_close(bio, BIO_NOCLOSE);
//   BIO_free_all(bio);

//   *base64Text=(*bufferPtr).data;
// }

std::string base64Encode(std::string input_text)
{
const unsigned char *input = reinterpret_cast<const unsigned char*>(input_text.c_str());
int length = input_text.size();
  BIO *bmem, *b64;
  BUF_MEM *bptr;
 
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
 
  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;
 
  BIO_free_all(b64);
  std::string output = buff;
  return output;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

// char* signMessage(std::string privateKey, std::string plainText) {
//   RSA* privateRSA = createPrivateRSA(privateKey); 
//   unsigned char* encMessage;
//   char* base64Text;
//   size_t encMessageLength;
//   RSASign(privateRSA, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
//   Base64Encode(encMessage, encMessageLength, &base64Text);
//   free(encMessage);
//   return base64Text;
// }

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
  RSA* publicRSA = createPublicRSA(publicKey);
  unsigned char* encMessage;
  size_t encMessageLength;
  bool authentic;
  Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
  return result & authentic;
}

// OLD FUNCTION, USELESS NOW

// https://stackoverflow.com/questions/29416549/getting-hash-of-a-binary-file-c
// std::string getFileBinaryHashb64(std::string fileName){
// std::string command = "openssl dgst -binary -sha256 "+fileName+" | openssl base64";
// const char *func_command = command.c_str();
//   FILE *fpipe; // Initializing FILE pointer to get the contents of the pipe
//   char c = 0; // Character for reading output
//   int pos = 0;
//   std::string output{}; // Output of each path
//   fpipe = (FILE *)popen(func_command, "r"); //Read the output pipe of the command
//   while (fread(&c, sizeof c, 1, fpipe)) {
//     output += c;
//   }
//   pos = output.find('\n');
//   output.erase(pos);
//   // std::cout << output << '\n';
//   pclose(fpipe);
//   return output;

// }

std::string getFileBinaryHashb64(std::string fileName){
unsigned char result[2*SHA256_DIGEST_LENGTH];
unsigned char hash[SHA256_DIGEST_LENGTH];
int i;
FILE *f = fopen(fileName.c_str(),"rb");
SHA256_CTX sha256;
int bytes;
unsigned char data[1024];
if(f == NULL){
    std::cout << "Couldnt open file:" << fileName << '\n';
    exit(1);
}
SHA256_Init(&sha256);
while((bytes = fread(data, 1, 1024, f)) != 0){
    SHA256_Update(&sha256, data, bytes);
}
SHA256_Final(hash, &sha256);

// for(i=0;i<SHA256_DIGEST_LENGTH;i++){
//     temp2[i] = hash[i];
// }
fclose(f);
// Store the char array into string
std::string str( hash, hash + sizeof (hash) / sizeof (hash[0]) );
// Obtain the base64 encoded value of the ascii string
std::string b64text = base64Encode(str);
return b64text;
}

// General File reading function
std::string readFile(std::string location){
  ifstream MyFile(location);
  std::string placeholder;
  std::string output;
  while (getline (MyFile, placeholder)) {
    output +=placeholder;
    output +='\n';
  }
  return output;
}

// SignedInfo should not be appended with a newline
std::string readSignedInfo(std::string location){
  ifstream MyFile(location);
  std::string placeholder;
  std::string output;
  while (getline (MyFile, placeholder)) {
    output +=placeholder;
  }
  return output;
}
