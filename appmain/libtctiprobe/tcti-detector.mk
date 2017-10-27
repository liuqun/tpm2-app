# Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)

# Each ".mk" file is used to build single executable file or object files

OBJECTS += tcti-detector.o
TCTI_DETECTOR_CFLAGS = $(TCTI_CFLAGS)
tcti-detector.o: CFLAGS+=$(TCTI_DETECTOR_CFLAGS)
