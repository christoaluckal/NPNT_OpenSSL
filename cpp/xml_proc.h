#include "../pugi/pugixml.hpp"
#include <iostream>
#include <assert.h>
#include <memory>
#include <string>  
#include <fstream>
#include <sstream> 
using namespace std;
void savePermissionInfo(std::string path);
void saveSignedInfo(std::string path);
void saveX509Key(std::string path);
std::string getSignatureValue(std::string path);
std::string getDigestValue(std::string path);
void cleanXml(std::string path);
void parseXML(std::string path_to_signed_xml);
void updateDigestValue(std::string path,std::string new_digest);