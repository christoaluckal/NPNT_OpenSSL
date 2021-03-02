/*
 * Canonical XML implementation test program
 * (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */

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


static void usage(const char *name) {
    fprintf(stderr,
	"Usage: %s <mode> <xml-file> [<xpath-expr>] [<inclusive-ns-list>]\n",
	    name);
    fprintf(stderr, "where <mode> is one of following:\n");
    fprintf(stderr,
	"--with-comments       \t XML file canonization w comments\n");
    fprintf(stderr,
	"--without-comments    \t XML file canonization w/o comments\n");
    fprintf(stderr,
    "--exc-with-comments   \t Exclusive XML file canonization w comments\n");
    fprintf(stderr,
    "--exc-without-comments\t Exclusive XML file canonization w/o comments\n");
}

xmlXPathObjectPtr
load_xpath_expr (xmlDocPtr parent_doc, const char* filename);

xmlChar **parse_list(xmlChar *str);

void print_xpath_nodes(xmlNodeSetPtr nodes);

std::string 
test_c14n(const char* xml_filename, int with_comments, int exclusive,
	const char* xpath_filename, xmlChar **inclusive_namespaces) {
    xmlDocPtr doc;
    xmlXPathObjectPtr xpath = NULL; 
    xmlChar *result = NULL;
    int ret;
    std::string finresult;
    /*
     * build an XML tree from a the file; we need to add default
     * attributes and resolve all character and entities references
     */
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(xml_filename);
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_filename);
	return("-1");
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
        fprintf(stderr,"Error: empty document for file \"%s\"\n", xml_filename);
	xmlFreeDoc(doc);
	return("-1");
    }

    /* 
     * load xpath file if specified 
     */
    if(xpath_filename) {
	xpath = load_xpath_expr(doc, xpath_filename);
	if(xpath == NULL) {
	    fprintf(stderr,"Error: unable to evaluate xpath expression\n");
	    xmlFreeDoc(doc); 
	    return("-1");
	}
    }

    /*
     * Canonical form
     */      
    /* fprintf(stderr,"File \"%s\" loaded: start canonization\n", xml_filename); */
    ret = xmlC14NDocDumpMemory(doc, 
	    (xpath) ? xpath->nodesetval : NULL, 
	    exclusive, inclusive_namespaces,
	    with_comments, &result);
    if(ret >= 0) {
	if(result != NULL) {
	    finresult = reinterpret_cast<const char *>(result);
	    xmlFree(result);          
	}
    } else {
	fprintf(stderr,"Error: failed to canonicalize XML file \"%s\" (ret=%d)\n", xml_filename, ret);
	if(result != NULL) xmlFree(result);
	xmlFreeDoc(doc); 
	return("-1");
    }
        
    /*
     * Cleanup
     */ 
    if(xpath != NULL) xmlXPathFreeObject(xpath);
    xmlFreeDoc(doc);    

    return(finresult);
}

// int main(int argc, char **argv) {
//     int ret = -1;
    
//     /*
//      * Init libxml
//      */     
//     xmlInitParser();
//     LIBXML_TEST_VERSION
//     ret = test_c14n(argv[2], 0, 0, (argc > 3) ? argv[3] : NULL, NULL);
//     // /* 
//     //  * Shutdown libxml
//     //  */
    
//     xmlCleanupParser();
//     xmlMemoryDump();
    
//     return((ret >= 0) ? 0 : 1);
// }

std::string finC14N(std::string path){
    int ret;
    xmlInitParser();
    LIBXML_TEST_VERSION
    std::string result = test_c14n(path.c_str(), 0, 0, NULL, NULL);
    xmlCleanupParser();
    xmlMemoryDump();
    return result;
}

/*
 * Macro used to grow the current buffer.
 */
#define growBufferReentrant() {						\
    buffer_size *= 2;							\
    buffer = (xmlChar **)						\
    		xmlRealloc(buffer, buffer_size * sizeof(xmlChar*));	\
    if (buffer == NULL) {						\
	perror("realloc failed");					\
	return(NULL);							\
    }									\
}

xmlChar **parse_list(xmlChar *str) {
    xmlChar **buffer;
    xmlChar **out = NULL;
    int buffer_size = 0;
    int len;

    if(str == NULL) {
	return(NULL);
    }
    // This was changed for the g++ compiler and is not present in the libxml code
    len = strlen(reinterpret_cast<const char *>(str));
    if((str[0] == '\'') && (str[len - 1] == '\'')) {
	str[len - 1] = '\0';
	str++;
	len -= 2;
    }
    /*
     * allocate an translation buffer.
     */
    buffer_size = 1000;
    buffer = (xmlChar **) xmlMalloc(buffer_size * sizeof(xmlChar*));
    if (buffer == NULL) {
	perror("malloc failed");
	return(NULL);
    }
    out = buffer;
    
    while(*str != '\0') {
	if (out - buffer > buffer_size - 10) {
	    int indx = out - buffer;

	    growBufferReentrant();
	    out = &buffer[indx];
	}
	(*out++) = str;
	while(*str != ',' && *str != '\0') ++str;
	if(*str == ',') *(str++) = '\0';
    }
    (*out) = NULL;
    return buffer;
}

xmlXPathObjectPtr
load_xpath_expr (xmlDocPtr parent_doc, const char* filename) {
    xmlXPathObjectPtr xpath; 
    xmlDocPtr doc;
    xmlChar *expr;
    xmlXPathContextPtr ctx; 
    xmlNodePtr node;
    xmlNsPtr ns;
    
    /*
     * load XPath expr as a file
     */
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(filename);
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", filename);
	return(NULL);
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
        fprintf(stderr,"Error: empty document for file \"%s\"\n", filename);
	xmlFreeDoc(doc);
	return(NULL);
    }

    node = doc->children;
    while(node != NULL && !xmlStrEqual(node->name, (const xmlChar *)"XPath")) {
	node = node->next;
    }
    
    if(node == NULL) {   
        fprintf(stderr,"Error: XPath element expected in the file  \"%s\"\n", filename);
	xmlFreeDoc(doc);
	return(NULL);
    }

    expr = xmlNodeGetContent(node);
    if(expr == NULL) {
        fprintf(stderr,"Error: XPath content element is NULL \"%s\"\n", filename);
	xmlFreeDoc(doc);
	return(NULL);
    }

    ctx = xmlXPathNewContext(parent_doc);
    if(ctx == NULL) {
        fprintf(stderr,"Error: unable to create new context\n");
        xmlFree(expr); 
        xmlFreeDoc(doc); 
        return(NULL);
    }

    /*
     * Register namespaces
     */
    ns = node->nsDef;
    while(ns != NULL) {
	if(xmlXPathRegisterNs(ctx, ns->prefix, ns->href) != 0) {
	    fprintf(stderr,"Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", ns->prefix, ns->href);
    	    xmlFree(expr); 
	    xmlXPathFreeContext(ctx); 
	    xmlFreeDoc(doc); 
	    return(NULL);
	}
	ns = ns->next;
    }

    /*  
     * Evaluate xpath
     */
    xpath = xmlXPathEvalExpression(expr, ctx);
    if(xpath == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression\n");
    	xmlFree(expr); 
        xmlXPathFreeContext(ctx); 
        xmlFreeDoc(doc); 
        return(NULL);
    }

    /* print_xpath_nodes(xpath->nodesetval); */

    xmlFree(expr); 
    xmlXPathFreeContext(ctx); 
    xmlFreeDoc(doc); 
    return(xpath);
}

void
print_xpath_nodes(xmlNodeSetPtr nodes) {
    xmlNodePtr cur;
    int i;
    
    if(nodes == NULL ){ 
	fprintf(stderr, "Error: no nodes set defined\n");
	return;
    }
    
    fprintf(stderr, "Nodes Set:\n-----\n");
    for(i = 0; i < nodes->nodeNr; ++i) {
	if(nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
	    xmlNsPtr ns;
	    
	    ns = (xmlNsPtr)nodes->nodeTab[i];
	    cur = (xmlNodePtr)ns->next;
	    fprintf(stderr, "namespace \"%s\"=\"%s\" for node %s:%s\n", 
		    ns->prefix, ns->href,
		    (cur->ns) ? cur->ns->prefix : BAD_CAST "", cur->name);
	} else if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
	    cur = nodes->nodeTab[i];    
	    fprintf(stderr, "element node \"%s:%s\"\n", 
		    (cur->ns) ? cur->ns->prefix : BAD_CAST "", cur->name);
	} else {
	    cur = nodes->nodeTab[i];    
	    fprintf(stderr, "node \"%s\": type %d\n", cur->name, cur->type);
	}
    }
}





// #else
// #include <stdio.h>
// int main(int argc, char **argv) {
//     printf("%s : XPath/Canonicalization support not compiled in\n", argv[0]);
//     return(0);
// }
// #endif /* LIBXML_C14N_ENABLED */


