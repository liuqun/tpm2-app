# Modified by liuqun <qunliu@zyhx-group.com>

CROSS_COMPILE =
#CROSS_COMPILE = arm-hisiv100nptl-linux-
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
STRIP = $(CROSS_COMPILE)strip
LIBS = 
CFLAGS = -Wall -g -O0
CXXFLAGS = $(CFLAGS)
INCLUDE = -I.


OBJS := SHA1.o
TARGET_1_OBJS += example_c.o
TARGET_2_OBJS += example_cpp.o

TARGET_1 = example_c
TARGET_2 = example_cpp

all: $(TARGET_1) $(TARGET_2)

$(TARGET_1): $(OBJS) $(TARGET_1_OBJS)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LIBS)

$(TARGET_2): $(OBJS) $(TARGET_2_OBJS)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LIBS)

SHA1.o : SHA1.cpp SHA1.h
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

example_c.o : example.c SHA1.h
	$(CC) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

example_cpp.o : example.cpp SHA1.h
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET_1_OBJS) $(TARGET_2_OBJS) $(TARGET_1) $(TARGET_2)
