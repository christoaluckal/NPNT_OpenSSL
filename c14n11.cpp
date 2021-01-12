#include <iostream>
using namespace std;

int main(){
    std::string xml_name;
    cout << "Enter the xml name" << '\n';
    cin >> xml_name;
    std::string c14n11_cmd = "xmllint -c14n11 "+xml_name+" > c14n_"+xml_name;
    system(c14n11_cmd.c_str());
    return 0;
}