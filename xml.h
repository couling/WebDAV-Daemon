#ifndef xml_h
#define xml_h

#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>

// XML Reader
void xmlReaderSuppressErrors(xmlTextReaderPtr reader);
int stepInto(xmlTextReaderPtr reader);
int stepOver(xmlTextReaderPtr reader);
int stepOut(xmlTextReaderPtr reader);
int stepOverText(xmlTextReaderPtr reader, const char ** text);
int elementMatches(xmlTextReaderPtr reader, const char * namespace, const char * nodeName);
const char * nodeTypeToName(int nodeType);

// XML Writer
xmlTextWriterPtr xmlNewFdTextWriter(int out);
int xmlTextWriterWriteElementString(xmlTextWriterPtr writer, const char * prefix, const char * elementName,
		const char * string);
void xmlTextWriterWriteURL(xmlTextWriterPtr writer, const char * url);

#endif
