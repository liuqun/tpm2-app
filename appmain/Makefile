# Makefile for TPM 2.0 application main entrance

.PHONY: default
default: main

.PHONY: all
all: default cscope tags

# PREFIX should be the same dir where TPM2.0-TSS libraries has been installed to
PREFIX := /usr/local
LOCAL_INCLUDE_DIRS := \
    -I$(PREFIX)/include \
    -I$(PREFIX)/include/sapi \
    -I$(PREFIX)/include/tcti \
    $(NULL)
LOCAL_LIB_DIR := $(PREFIX)/lib
SAPI_LIB := -L$(LOCAL_LIB_DIR) -lsapi
TCTI_DEVICE_LIB := -L$(LOCAL_LIB_DIR) -ltcti-device
TCTI_SOCKET_LIB := -L$(LOCAL_LIB_DIR) -ltcti-socket
MARSHAL_LIB := -L$(LOCAL_LIB_DIR) -lmarshal

#
LIBS := $(SAPI_LIB) $(TCTI_DEVICE_LIB) $(TCTI_SOCKET_LIB) $(MARSHAL_LIB)
CFLAGS := -g -O0 -Wall $(LOCAL_INCLUDE_DIRS)
CXXFLAGS := $(CFLAGS)
COMPILE_c = $(COMPILE.c)
COMPILE_cpp = $(COMPILE.cpp)

# 输入输出文件
SRC_FILES := $(wildcard *.cpp)
SRC_FILES_WITHOUT_SUFFIX = $(basename $(SRC_FILES))
OBJ_FILES = $(patsubst %, %.o, $(SRC_FILES_WITHOUT_SUFFIX))

.PHONY: ALWAYS_REBUILD
libplugin.a: ALWAYS_REBUILD
	rm -f libplugin/$@
	$(MAKE) -C libplugin $@
	cp libplugin/$@ ./$@

main.o: main.cpp TPMCommand.h TestCase.h
	$(COMPILE_cpp) -o $@ $<

TestCase.o: TestCase.cpp TestCase.h TPMCommand.h
	$(COMPILE_cpp) -o $@ $<

main: $(OBJ_FILES) libplugin.a
	$(CXX) $(LD_FLAGS) -o $@ $^ $(LIBS)

%.o: %.c %.h
	$(COMPILE_c) -o $@ $<

%.o: %.c
	$(COMPILE_c) -o $@ $<

%.o: %.cpp %.h
	$(COMPILE_cpp) -o $@ $<

%.o: %.cpp
	$(COMPILE_cpp) -o $@ $<

.PHONY: clean
clean:
	$(MAKE) clean -C libplugin
	$(RM) libplugin.a
	$(RM) *.o
	$(RM) cscope.files cscope.out
	$(RM) TAGS

.PHONY: cscope
cscope: cscope.out
cscope.out: cscope.files
	cscope -R -b -i $<
cscope.files: ALWAYS_UPDATE_FILE_LIST
	find . -name "*.cpp" -or -name "*.[ch]" > $@
# Always updete the file list for TAGS and cscope, so ther will update symbol table from source files
.PHONY: ALWAYS_UPDATE_FILE_LIST

.PHONY: tags
tags: TAGS
TAGS: cscope.files
	cat $^ | etags - -o $@
