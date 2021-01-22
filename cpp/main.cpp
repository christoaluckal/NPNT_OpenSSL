#include<iostream>
#include "xml_proc.h"
#include "createsign.h"

// All verification files are made in temp directory
void makeTemp(){
    std::string command = "mkdir temp";
    system(command.c_str());
    return;
}

// openSSL command is used to extract public key from the certificate generated during parseXML()
void genPubKey(){
    std::string command = "openssl x509 -pubkey -noout -in temp/pugi_certificate.pem > temp/pugi_gen_public.pem";
    system(command.c_str());
    return;
}

// We delete the temp folder after verification is performed regardless of success
void deleteTemp(){
    std::string command = "rm -rf temp";
    system(command.c_str());
    std::cout << "Deleted temp" << '\n';
}

int main(int argc, char *argv[])
{
    std::string signed_xml = argv[1]; // The signed XML document is passed as an argument
    makeTemp();
    parseXML(signed_xml); // This creates the canonicalized permission and signedinfo subtrees as well as the x509 certificate file
    genPubKey();
    std::string hash = getFileBinaryHashb64("temp/c14n_pugi_PI.xml"); // We parse the canonicalized permission information and hash it (SHA-256)
    std::string digestvalue = getDigestValue(signed_xml); // We also extract the DigestValue from the SignedInfo tag
    // std::cout << "B64:  " << hash << '\n' << "DV:   " << digestvalue << '\n';
    // std::cout << strcmp(hash.c_str(),digestvalue.c_str()) << '\n';
    
    std::string publicKey,signatureValue,c14SignedInfo;
    publicKey = readFile("temp/pugi_gen_public.pem"); // We read the public key required for verification
    signatureValue = getSignatureValue(signed_xml); // We extract the SignatureValue from the signed XML
    // std::cout << c14SignedInfo << '\n';
    updateDigestValue("temp/c14n_pugi_SI.xml",hash); // Here we update the SignedInfo with the digest value that was calculated above. If the signature is valid, the new DigestValue will be the same
    cleanXml("temp/c14n_pugi_SI.xml"); // We re-canonicalize it. TODO Check why it uncanonicalizes
    c14SignedInfo = readSignedInfo("temp/c14n_c14n_pugi_SI.xml"); // We convert the canonicalized and updated SignedInfo into string for verification
    // std::cout << c14SignedInfo << '\n';
    signatureValue.append("\n"); // Currently the signature needs to be appended with a new-line
    char signature[signatureValue.length()+1]; // Copy the string into a char* because the verifier needs it in char*
    strcpy(signature,signatureValue.c_str());
    bool authentic = verifySignature(publicKey,c14SignedInfo,signature); // Perform Verification
    if(authentic){
        std::cout << "Signature is Valid" << '\n';
        deleteTemp();
        return EXIT_SUCCESS;
    }
    else{
        std::cout << "Invalid Signature" << '\n';
        deleteTemp();
        return EXIT_FAILURE;
    }
    
}