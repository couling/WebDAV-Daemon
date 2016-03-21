#include "xml.h"

#include "shared.h"

#include <stddef.h>
#include <string.h>
#include <unistd.h>

////////////////
// XML Reader //
////////////////

static void xmlTextNOOPErrorFunction(void * arg, const char * msg, xmlParserSeverities severity,
		xmlTextReaderLocatorPtr locator) {
}

void xmlReaderSuppressErrors(xmlTextReaderPtr reader) {
	xmlTextReaderSetErrorHandler(reader, &xmlTextNOOPErrorFunction, NULL);
}

int stepInto(xmlTextReaderPtr reader) {
	// Skip all significant white space
	int result;
	do {
		result = xmlTextReaderRead(reader);
	} while (result
			&& (xmlTextReaderNodeType(reader) == XML_READER_TYPE_SIGNIFICANT_WHITESPACE
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_COMMENT
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT));
	return result;
}

int stepOver(xmlTextReaderPtr reader) {
	int depth = xmlTextReaderDepth(reader);
	int result;
	do {
		result = xmlTextReaderRead(reader);
	} while (result && xmlTextReaderDepth(reader) > depth);
	while (result
			&& (xmlTextReaderNodeType(reader) == XML_READER_TYPE_SIGNIFICANT_WHITESPACE
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_COMMENT
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)) {
		result = xmlTextReaderRead(reader);
	}
	return result;
}

int stepOut(xmlTextReaderPtr reader) {
	int depth = xmlTextReaderDepth(reader) - 1;
	int result;
	do {
		result = xmlTextReaderRead(reader);
	} while (result && xmlTextReaderDepth(reader) > depth);
	while (result
			&& (xmlTextReaderNodeType(reader) == XML_READER_TYPE_SIGNIFICANT_WHITESPACE
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_COMMENT
					|| xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)) {
		result = xmlTextReaderRead(reader);
	}
	return result;
}

int stepOverText(xmlTextReaderPtr reader, const char ** text) {
	int depth = xmlTextReaderDepth(reader);
	int result = stepInto(reader);
	*text = NULL;
	if (result && xmlTextReaderDepth(reader) > depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
			*text = xmlTextReaderValue(reader);
		}
		result = stepOut(reader);
	}
	return result;
}

int elementMatches(xmlTextReaderPtr reader, const char * namespace, const char * nodeName) {
	return xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
			&& !strcmp(xmlTextReaderConstNamespaceUri(reader), namespace)
			&& !strcmp(xmlTextReaderConstLocalName(reader), nodeName);
}

const char * nodeTypeToName(int nodeType) {
	switch (nodeType) {
	case XML_READER_TYPE_NONE:
		return "XML_READER_TYPE_NONE";
	case XML_READER_TYPE_ELEMENT:
		return "XML_READER_TYPE_ELEMENT";
	case XML_READER_TYPE_ATTRIBUTE:
		return "XML_READER_TYPE_ATTRIBUTE";
	case XML_READER_TYPE_TEXT:
		return "XML_READER_TYPE_TEXT";
	case XML_READER_TYPE_CDATA:
		return "XML_READER_TYPE_CDATA";
	case XML_READER_TYPE_ENTITY_REFERENCE:
		return "XML_READER_TYPE_ENTITY_REFERENCE";
	case XML_READER_TYPE_ENTITY:
		return "XML_READER_TYPE_ENTITY";
	case XML_READER_TYPE_PROCESSING_INSTRUCTION:
		return "XML_READER_TYPE_PROCESSING_INSTRUCTION";
	case XML_READER_TYPE_COMMENT:
		return "XML_READER_TYPE_COMMENT";
	case XML_READER_TYPE_DOCUMENT:
		return "XML_READER_TYPE_DOCUMENT";
	case XML_READER_TYPE_DOCUMENT_TYPE:
		return "XML_READER_TYPE_DOCUMENT_TYPE";
	case XML_READER_TYPE_DOCUMENT_FRAGMENT:
		return "XML_READER_TYPE_DOCUMENT_FRAGMENT";
	case XML_READER_TYPE_NOTATION:
		return "XML_READER_TYPE_NOTATION";
	case XML_READER_TYPE_WHITESPACE:
		return "XML_READER_TYPE_WHITESPACE";
	case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
		return "XML_READER_TYPE_SIGNIFICANT_WHITESPACE";
	case XML_READER_TYPE_END_ELEMENT:
		return "XML_READER_TYPE_END_ELEMENT";
	case XML_READER_TYPE_END_ENTITY:
		return "XML_READER_TYPE_END_ENTITY";
	case XML_READER_TYPE_XML_DECLARATION:
		return "XML_READER_TYPE_XML_DECLARATION";
	default:
		return NULL;
	}
}

////////////////////
// End XML Reader //
////////////////////

/////////////////////
// XML Text Writer //
/////////////////////

static int xmlFdOutputCloseCallback(void * context) {
	close(*((int *) context));
	freeSafe(context);
	return 0;
}

static int xmlFdOutputWriteCallback(void * context, const char * buffer, int len) {
	ssize_t ignored = write(*((int *) context), buffer, len);
	return ignored;
}

xmlTextWriterPtr xmlNewFdTextWriter(int out) {
	xmlOutputBufferPtr outStruct = xmlAllocOutputBuffer(NULL);
	outStruct->writecallback = &xmlFdOutputWriteCallback;
	outStruct->closecallback = &xmlFdOutputCloseCallback;
	outStruct->context = mallocSafe(sizeof(int));
	*((int *) outStruct->context) = out;
	return xmlNewTextWriter(outStruct);
}

int xmlTextWriterWriteElementString(xmlTextWriterPtr writer, const char * prefix, const char * elementName,
		const char * string) {
	int ret;
	//if (prefix) {
	if ((ret = xmlTextWriterStartElementNS(writer, prefix, elementName, NULL)) < 0) return ret;
	//} else {
	//	if ((ret = xmlTextWriterStartElement(writer, elementName)) < 0)
	//		return ret;
	//}
	if (string && (ret = xmlTextWriterWriteString(writer, string)) < 0) return ret;
	if ((ret = xmlTextWriterEndElement(writer)) < 0) return ret;
	return ret;
}

void xmlTextWriterWriteURL(xmlTextWriterPtr writer, const char * url) {
	char buffer[1024];
	const char * urlPtr = url;
	char * writePtr = buffer;
	unsigned char c;
	while ((c = *(urlPtr++))) {
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_'
				|| c == '.' || c == '~' || c == '/') {
			*(writePtr++) = c;
		} else {
			static const char * lookup = "0123456789ABCDEF";
			*(writePtr++) = '%';
			*(writePtr++) = lookup[(c & 0xF0) >> 4];
			*(writePtr++) = lookup[c & 0x0F];
		}
		if (writePtr > buffer + sizeof(buffer) - 5) {
			*writePtr = '\0';
			xmlTextWriterWriteString(writer, buffer);
			writePtr = buffer;
		}
	}
	*writePtr = '\0';
	xmlTextWriterWriteString(writer, buffer);
}

/////////////////////////
// End XML Text Writer //
/////////////////////////

