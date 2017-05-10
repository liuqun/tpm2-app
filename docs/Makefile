# Makefile for project documents

DOXYGEN = doxygen
DOXYGEN_CONF = ./doxygen.conf
DOCUMENTS = html rtf latex man xml

.PHONY: all
all:
	$(DOXYGEN) $(DOXYGEN_CONF)
.PHONY: clean
clean:
	$(RM) -rf $(DOCUMENTS)
