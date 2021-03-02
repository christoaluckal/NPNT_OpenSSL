// /* ------------------------------------------------------------ *
//  * file:        certpubkey.c                                    *
//  * purpose:     Example code to extract public keydata in certs *
//  * author:      09/24/2012 Frank4DD                             *
//  *                                                              *
//  * gcc -o certpubkey certpubkey.c -lssl -lcrypto                *
//  * ------------------------------------------------------------ */

// #include <openssl/bio.h>
// #include <openssl/err.h>
// #include <openssl/pem.h>
// #include <openssl/x509.h>
// #include <iostream>
// #include <sstream>
// #include <cstring>
// #include <iostream>

// char *X509_to_PEM(EVP_PKEY *key) {

//     BIO *bio = NULL;
//     char *pem = NULL;

//     if (NULL == key) {
//         return NULL;
//     }

//     bio = BIO_new(BIO_s_mem());
//     if (NULL == bio) {
//         return NULL;
//     }

//     if (0 == PEM_write_bio_PUBKEY(bio, key)) {
//         BIO_free(bio);
//         return NULL;
//     }

//     pem = (char *) malloc(bio->num_write + 1);
//     if (NULL == pem) {
//         BIO_free(bio);
//         return NULL;    
//     }

//     memset(pem, 0, bio->num_write + 1);
//     BIO_read(bio, pem, bio->num_write);
//     BIO_free(bio);
//     return pem;
// }

// std::string getPublicKey(std::string path)
// {
// const char *cert_filestr = path.c_str();
//              EVP_PKEY *pkey = NULL;
//   BIO              *certbio = NULL;
//   BIO               *outbio = NULL;
//   X509                *cert = NULL;
//   int ret;

//   /* ---------------------------------------------------------- *
//    * These function calls initialize openssl for correct work.  *
//    * ---------------------------------------------------------- */
//   OpenSSL_add_all_algorithms();
//   ERR_load_BIO_strings();
//   ERR_load_crypto_strings();

//   /* ---------------------------------------------------------- *
//    * Create the Input/Output BIO's.                             *
//    * ---------------------------------------------------------- */
//   certbio = BIO_new(BIO_s_file());
//   outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

//   /* ---------------------------------------------------------- *
//    * Load the certificate from file (PEM).                      *
//    * ---------------------------------------------------------- */
//   ret = BIO_read_filename(certbio, cert_filestr);
//   if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
//     BIO_printf(outbio, "Error loading cert into memory\n");
//     exit(-1);
//   }

//   /* ---------------------------------------------------------- *
//    * Extract the certificate's public key data.                 *
//    * ---------------------------------------------------------- */
//   if ((pkey = X509_get_pubkey(cert)) == NULL)
//     BIO_printf(outbio, "Error getting public key from certificate");

//   /* ---------------------------------------------------------- *
//    * Print the public key information and the key in PEM format *
//    * ---------------------------------------------------------- */
//   /* display the key type and size here */
// //   if (pkey) {
// //     BIO_printf(outbio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
// //   }
//   std::string kekw;
//   if(!PEM_write_bio_PUBKEY(outbio, pkey))
//     BIO_printf(outbio, "Error writing public key data in PEM format");
//     // char* rawBuffer;
//     // int buffSize = 1000;
//     // BIO_read( outbio, rawBuffer, buffSize );

//     // std::cout << "BUFFER    " << *rawBuffer;
//     char *pubkey = X509_to_PEM(pkey);
//   EVP_PKEY_free(pkey);
//   X509_free(cert);
//   BIO_free_all(certbio);
//   BIO_free_all(outbio);
//   return kekw;
// }


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