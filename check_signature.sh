cd cpp
g++ main.cpp xml_proc.cpp createsign.cpp testC14N.cpp key.cpp -I/usr/include/libxml2 ../pugi/pugixml.cpp -lcrypto -lxml2
./a.out ../xmls/fin_signed.xml