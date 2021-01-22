cd cpp
g++ main.cpp xml_proc.cpp ../pugi/pugixml.cpp createsign.cpp -lcrypto
./a.out ../xmls/fin_signed.xml