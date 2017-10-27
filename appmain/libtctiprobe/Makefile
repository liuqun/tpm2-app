# Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)
# Makefile for my sample program

.PHONY: all
all:

src_DIR := $(shell pwd)
config_FILES := config.h config.h.in config.mk
test_PROGRAMS :=
OBJECTS :=
test_OBJECTS :=

vpath %test.c test
vpath %test.cpp test
-include *.mk

LIBNAME = libtctiprobe
lib_OBJECTS = $(patsubst %, $(LIBNAME).a(%), $(OBJECTS))

CUSTOMIZED_LIBS =
LIBS += $(CUSTOMIZED_LIBS)

CUSTOMIZED_CFLAGS = -Wunused-parameter -I$(src_DIR)
CFLAGS += $(CUSTOMIZED_CFLAGS)

CUSTOMIZED_CXXFLAGS = $(CUSTOMIZED_CFLAGS)
CXXFLAGS += $(CUSTOMIZED_CXXFLAGS)

all: $(config_FILES)
	$(MAKE) $(LIBNAME).a $(OBJECTS) tests

$(LIBNAME).a: $(lib_OBJECTS)

config.%: config.%.in
	$(MAKE) defconfig

configure config.h.in: configure.ac
	autoreconf --install
	chmod +x ./configure

.PHONY: defconfig
defconfig: configure
	./configure

.PHONY: tests
tests: $(test_PROGRAMS)

%.o: %.cpp %.h
	$(COMPILE.cpp) -o $@ $<

%.o: %.cpp
	$(COMPILE.cpp) -o $@ $<

%.o: %.c %.h
	$(COMPILE.c) -o $@ $<

%.o: %.c
	$(COMPILE.c) -o $@ $<

.PHONY: clean
clean:
	$(RM) $(bin_PROGRAMS) $(sbin_PROGRAMS) $(test_PROGRAMS) *.o *.a

# vim: ts=4 sw=4
