# Makefile

.PHONY: tests
tests: test-asymmetric-encrypt-decrypt

.PHONY: all
all: tests

# PREFIX should be the same dir where TPM2.0-TSS libraries has been installed to
PREFIX := /usr/local

# Build options:
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
LIBS := $(SAPI_LIB) $(TCTI_DEVICE_LIB) $(TCTI_SOCKET_LIB) $(MARSHAL_LIB)
CFLAGS := -g -O0 -Wall $(LOCAL_INCLUDE_DIRS)
CXXFLAGS := $(CFLAGS)
COMPILE_c = $(COMPILE.c)
COMPILE_cpp = $(COMPILE.cpp)

# Build Rules
test-asymmetric-encrypt-decrypt: test-main.o asymmetric-encrypt-decrypt.o
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
	$(RM) *.o
