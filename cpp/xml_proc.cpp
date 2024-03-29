#include "../pugi/pugixml.hpp"
#include "testC14N.h"
#include <iostream>
#include <assert.h>
#include <memory>
#include <string>  
#include <fstream>
#include <sstream>  
using namespace std;

// Print the XML tree.

// struct simple_walker: pugi::xml_tree_walker
// {
//     virtual bool for_each(pugi::xml_node& node)
//     {
//         for (int i = 0; i < depth(); ++i) std::cout << "  "; // indentation

//         std::cout << ": name='" << node.name() << "', value='" << node.value() << "'\n";

//         return true; // continue traversal
//     }
// };

/*
Function to extract the base permission without signature.
param path: Path to the final signed XML file.
*/
void savePermissionInfo(std::string path){
    pugi::xml_document doc; // Root of the signed XML file.
    doc.load_file(path.c_str()); // Load the XML from path

    pugi::xml_document doc2; // New root for saving a subtree
    stringstream strstre; // The output is saved to the ostream and then loaded into another root.
    std::string signed_info; // Temporary string to hold the subtree string.
    doc.child("UAPermission").print(strstre, "", pugi::format_raw | pugi::format_no_declaration); // Save the entire tree into the ostream.
    signed_info = strstre.str(); // Get string form of the ostream.
    doc2.load_string(signed_info.c_str()); // Load the string into an empty root. Here signed_info: <UAPermission>...</UAPermission>
    doc2.child("UAPermission").remove_child("Signature"); // Keep only the Permission Tag and Remove the Signature Tag.
    doc2.save_file("temp/pugi_PI.xml","", pugi::format_raw | pugi::format_no_declaration); // Save to new XML file.
}

/*
Function to extract the signed info from the signed xml.
param path: Path to the final signed XML file.
*/
void saveSignedInfo(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());

    pugi::xml_document doc2;
    stringstream strstre;
    std::string signed_info;
    doc.child("UAPermission").child("Signature").child("SignedInfo").append_attribute("xmlns") = "http://www.w3.org/2000/09/xmldsig#"; // Add xmlns attribute with value to SignedInfo tag.
    doc.child("UAPermission").child("Signature").child("SignedInfo").print(strstre, "", pugi::format_raw | pugi::format_no_declaration);
    signed_info = strstre.str();
    doc2.load_string(signed_info.c_str());
    doc2.save_file("temp/pugi_SI.xml","", pugi::format_raw | pugi::format_no_declaration);

}


/*
Function to extract the base64 encoded x509 certificate string and save it as a new certificate.
param path: Path to the final signed XML file.
*/
void saveX509Key(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node x509key = doc.child("UAPermission").child("Signature").child("KeyInfo").child("X509Data").child("X509Certificate"); // Get the base64 encoded certificate value
    std::string x509_key = "-----BEGIN CERTIFICATE-----\n"; // Saving as the specified x509 certificate format.
    x509_key += x509key.first_child().value();
    x509_key += "-----END CERTIFICATE-----";
    std::ofstream out("temp/pugi_certificate.pem");
    out << x509_key;
    out.close();
}

/*
Function to canonicalize and remove the new-line at the end of the XML.
IMPORTANT for the signing and verification purposes.
param path: Path to the final signed XML file.
*/
void cleanXml(std::string path){
    // cout << "Enter Canonicalized name and Path for " << path << " eg. (../xmls/<name>)" << '\n';
    cout << "Saving " << "Canonicalized "<< path << " to " << "c14n_"+path.substr(5) << '\n';
    // std::string command = "xmllint -c14n11 "+path+"| tr -d '\\n' > temp/c14n_"+path.substr(5);
    std::string c14n = finC14N(path);
    std::string output = "temp/c14n_"+path.substr(5);
    std::ofstream out(output);
    out << c14n;
    out.close();
    // system(command.c_str());
}


/*
Function to extract the base64 encoded SignatureValue from the signed xml.
param path: Path to the final signed XML file.
*/
std::string getSignatureValue(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node sv = doc.child("UAPermission").child("Signature").child("SignatureValue");
    return sv.first_child().value();
}

void updateDigestValue(std::string path,std::string new_digest){
    pugi::xml_document doc;
    std::string updated_path;
    doc.load_file(path.c_str());
    pugi::xml_node dv = doc.child("SignedInfo").child("Reference").child("DigestValue");
    // std::cout << "CURRENT HASH IS:  " << dv.first_child().value() << '\n';
    // std::cout << "NEW HASH IS:  " << new_digest << '\n';
    dv.first_child().set_value(new_digest.c_str());
    // std::cout << "UPDATED HASH IS:  " << dv.first_child().value() << '\n';
    doc.save_file(path.c_str(),"", pugi::format_raw | pugi::format_no_declaration);
}

/*
Function to extract the base64 encoded DigestValue from the signed xml.
param path: Path to the final signed XML file.
*/
std::string getDigestValue(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());
    pugi::xml_node dv = doc.child("UAPermission").child("Signature").child("SignedInfo").child("Reference").child("DigestValue");
    return dv.first_child().value();
}


// int main()
// {
//     saveSignedInfo("../xmls/fin_signed.xml");
//     savePermissionInfo("../xmls/fin_signed.xml");
//     saveX509Key("../xmls/fin_signed.xml");
//     std::string signatureValue = getSignatureValue("../xmls/fin_signed.xml");
//     std::cout << "Signature Value:" << signatureValue << '\n';
//     std::string digestValue = getDigestValue("../xmls/fin_signed.xml");
//     std::cout << "Digest Value:" << digestValue << '\n';
//     cleanXml("../xmls/pugi_SI.xml");
//     cleanXml("../xmls/pugi_PI.xml");
// // simple_walker walker;
// // doc.traverse(walker);
// }

void parseXML(std::string path_to_signed_xml)
{
    saveSignedInfo(path_to_signed_xml);
    savePermissionInfo(path_to_signed_xml);
    saveX509Key(path_to_signed_xml);
    std::string signatureValue = getSignatureValue(path_to_signed_xml);
    std::string digestValue = getDigestValue(path_to_signed_xml);
    std::string temp1,temp2;
    cleanXml("temp/pugi_SI.xml");
    cleanXml("temp/pugi_PI.xml");
// simple_walker walker;
// doc.traverse(walker);
}