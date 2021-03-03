// https://cpp.hotexamples.com/examples/-/-/PEM_write_bio_PUBKEY/cpp-pem_write_bio_pubkey-function-examples.html#0xff56ac6fd14800b056f042736cc8f54290697d3659719397ca398ec98339465c-208,,246,

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <iostream>

std::string get_key_from_certfile(const char* certfile) {
  BIO* certbio = NULL;
  certbio = BIO_new_file(certfile, "r");
  X509* cert = NULL;
  cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL); 
  EVP_PKEY* key = NULL;
  key = X509_get_pubkey(cert);

  BIO* out = NULL;
  out = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(out, key);

  std::string pubkey_str;
  for(;;) {
    char s[256];
    int l = BIO_read(out,s,sizeof(s));
    if(l <= 0) break;
    pubkey_str.append(s,l);;
  }

  EVP_PKEY_free(key);
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(out);
  return pubkey_str;
}