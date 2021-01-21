#include "../pugi/pugixml.hpp"
#include <iostream>
#include <assert.h>
#include <memory>
#include <string>  
#include <fstream>
#include <sstream>  
using namespace std;


// struct simple_walker: pugi::xml_tree_walker
// {
//     virtual bool for_each(pugi::xml_node& node)
//     {
//         for (int i = 0; i < depth(); ++i) std::cout << "  "; // indentation

//         std::cout << ": name='" << node.name() << "', value='" << node.value() << "'\n";

//         return true; // continue traversal
//     }
// };

void savePermissionInfo(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());

    pugi::xml_document doc2;
    stringstream strstre;
    std::string signed_info;
    doc.child("UAPermission").print(strstre, "", pugi::format_raw | pugi::format_no_declaration);
    signed_info = strstre.str();
    doc2.load_string(signed_info.c_str());
    doc2.child("UAPermission").remove_child("Signature");
    doc2.save_file("../xmls/pugi_PI.xml","", pugi::format_raw | pugi::format_no_declaration);
}

void saveSignedInfo(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());

    pugi::xml_document doc2;
    stringstream strstre;
    std::string signed_info;
    doc.child("UAPermission").child("Signature").child("SignedInfo").append_attribute("xmlns") = "http://www.w3.org/2000/09/xmldsig#";
    doc.child("UAPermission").child("Signature").child("SignedInfo").print(strstre, "", pugi::format_raw | pugi::format_no_declaration);
    signed_info = strstre.str();
    doc2.load_string(signed_info.c_str());
    doc2.save_file("../xmls/pugi_SI.xml","", pugi::format_raw | pugi::format_no_declaration);
    // system("xmllint -c14n11 ../xmls/pugi_SI.xml | tr -d '\n' > ../xmls/pugi_head_SI.xml");
}

void saveX509Key(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node x509key = doc.child("UAPermission").child("Signature").child("KeyInfo").child("X509Data").child("X509Certificate");
    std::string x509_key = "-----BEGIN CERTIFICATE-----\n";
    x509_key += x509key.first_child().value();
    x509_key += "-----END CERTIFICATE-----";
    std::ofstream out("../keys/pugi_certificate.pem");
    out << x509_key;
    out.close();
}

std::string getSignatureValue(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node sv = doc.child("UAPermission").child("Signature").child("SignatureValue");
    return sv.first_child().value();
}

std::string getDigestValue(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node dv = doc.child("UAPermission").child("Signature").child("SignedInfo").child("Reference").child("DigestValue");
    return dv.first_child().value();
}

void cleanXml(std::string path){
    std::string c14path;
    cout << "Enter Canonicalized name and Path for " << path << " eg. (../xmls/<name>)" << '\n';
    cin >> c14path;
    cout << "Saving " << "Canonicalized "<< path << "to " << c14path << '\n';
    std::string command = "xmllint -c14n11 "+path+"| tr -d '\\n' > "+c14path;
    system(command.c_str());
}

int main()
{
    saveSignedInfo("../xmls/fin_signed.xml");
    savePermissionInfo("../xmls/fin_signed.xml");
    saveX509Key("../xmls/fin_signed.xml");
    std::string signatureValue = getSignatureValue("../xmls/fin_signed.xml");
    std::string digestValue = getDigestValue("../xmls/fin_signed.xml");
    cleanXml("../xmls/pugi_SI.xml");
    cleanXml("../xmls/pugi_PI.xml");
// simple_walker walker;
// doc.traverse(walker);
}