
#include <stdio.h>
#include <string.h>
// #ifdef HAVE_UNISTD_H
#include <unistd.h>
// #endif

#include <stdlib.h>
#include <iostream>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <libxml/c14n.h>


static void usage(const char *name);

xmlXPathObjectPtr load_xpath_expr (xmlDocPtr parent_doc, const char* filename);

xmlChar **parse_list(xmlChar *str);

void print_xpath_nodes(xmlNodeSetPtr nodes);

std::string
test_c14n(const char* xml_filename, int with_comments, int exclusive,
	const char* xpath_filename, xmlChar **inclusive_namespaces);

std::string finC14N(std::string path);