# Makefile for TPM commands
# encoding: utf-8
# Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
# All rights reserved.

# 输入输出文件
LIB_FILE := libplugin.a
SRC_FILES := $(wildcard *.cpp)
SRC_FILES_WITHOUT_SUFFIX = $(basename $(SRC_FILES))
OBJ_FILES = $(patsubst %, %.o, $(SRC_FILES_WITHOUT_SUFFIX))
LIBOBJ_FILES = $(patsubst %, libplugin.a(%), $(OBJ_FILES))

# 使用默认规则编译静态库
.PHONY: all
all: $(LIB_FILE)
$(LIB_FILE): $(LIBOBJ_FILES)

# PREFIX should be the same dir where TPM2.0-TSS libraries has been installed to
PREFIX := /usr/local

# 编译选项: 头文件路径设置
LOCAL_INCLUDE_DIRS := \
    -I.. \
    -I$(PREFIX)/include \
    -I$(PREFIX)/include/sapi \
    -I$(PREFIX)/include/tcti \
    $(NULL)
CFLAGS := -g -O0 -Wall $(LOCAL_INCLUDE_DIRS)
CXXFLAGS := $(CFLAGS)
COMPILE_c = $(COMPILE.c)
COMPILE_cpp = $(COMPILE.cpp)

# 编译选项: 外部动态库路径设置
LOCAL_LIB_DIR := $(PREFIX)/lib
SAPI_LIB := -L$(LOCAL_LIB_DIR) -lsapi
TCTI_DEVICE_LIB := -L$(LOCAL_LIB_DIR) -ltcti-device
TCTI_SOCKET_LIB := -L$(LOCAL_LIB_DIR) -ltcti-socket
MARSHAL_LIB := -L$(LOCAL_LIB_DIR) -lmarshal
LIBS := $(SAPI_LIB) $(TCTI_DEVICE_LIB) $(TCTI_SOCKET_LIB) $(MARSHAL_LIB)

# C/C++ 默认编译规则
%.o: %.c %.h
	$(COMPILE_c) -o $@ $<
%.o: %.c
	$(COMPILE_c) -o $@ $<
%.o: %.cpp %.h
	$(COMPILE_cpp) -o $@ $<
%.o: %.cpp
	$(COMPILE_cpp) -o $@ $<

# 清理规则
.PHONY: clean
clean:
	$(RM) *.o
	$(RM) cscope.files cscope.out
	$(RM) TAGS

# 其他: cscope 和 TAGS符号表
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
