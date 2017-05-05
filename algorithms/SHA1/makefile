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
OBJS += example.o 

TARGET_1 = example

all: $(TARGET_1)

$(TARGET_1): $(OBJS)
	$(CXX) $(LDFLAGS) $^ -o $(TARGET_1) $(LIBS)

SHA1.o : SHA1.c SHA1.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@ 

example.o : example.cpp SHA1.h
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@ 

clean:
	rm -rf $(OBJS) $(TARGET_1)
