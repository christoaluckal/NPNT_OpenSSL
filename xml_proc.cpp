#include "pugi/pugixml.hpp"
#include <iostream>
#include <assert.h>
#include <memory>
#include <string>  
#include <iostream> 
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

void getSignedInfo(std::string path){
    pugi::xml_document doc;
    doc.load_file(path.c_str());

    pugi::xml_document doc2;
    stringstream strstre;
    std::string temp;
    doc.child("UAPermission").child("Signature").child("SignedInfo").append_attribute("xmlns") = "http://www.w3.org/2000/09/xmldsig#";
    doc.child("UAPermission").child("Signature").child("SignedInfo").print(strstre, "", pugi::format_raw | pugi::format_no_declaration);
    temp = strstre.str();
    temp = strstre.str();
    doc2.load_string(temp.c_str());
    doc2.save_file("pugi_SI.xml","", pugi::format_raw | pugi::format_no_declaration);
}

int main()
{
        // Create empty XML document within memory
    pugi::xml_document doc;
    std::string namePerson;
    if (!doc.load_file("fin_signed.xml")) return -1;

    pugi::xml_node signed_info = doc.child("UAPermission").child("Signature").child("SignedInfo");
    pugi::xml_node c14n = signed_info.child("CanonicalizationMethod");
    pugi::xml_node sign_method = signed_info.child("SignatureMethod");
    pugi::xml_node reference = signed_info.child("Reference");
    pugi::xml_node sv = doc.child("UAPermission").child("Signature").child("SignatureValue");

    getSignedInfo("fin_signed.xml");
    // pugi::xml_document doc2;
    // stringstream strstre;
    // std::string temp;
    // doc.child("UAPermission").child("Signature").child("SignedInfo").print(strstre, "", pugi::format_raw | pugi::format_no_declaration);
    // temp = strstre.str();

    // temp = strstre.str();
    // cout << "\n\n\n" <<temp;

    // doc2.load_string(temp.c_str());
    // doc2.save_file("doc2.xml","", pugi::format_raw | pugi::format_no_declaration);
    
    
// simple_walker walker;
// doc.traverse(walker);


}