# Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)

# Each ".mk" file is used to build single executable file or object files

test_PROGRAMS += tcti-detector-test
tcti_detector_test_OBJECTS = tcti-detector-test.o
test_OBJECTS += $(tcti_detector_test_OBJECTS)
LIBDL_LIBS ?= -ldl
tcti_detector_test_LIBS = $(LIBDL_LIBS) $(TCTI_LIBS) $(SAPI_LIBS)
tcti-detector-test: LIBS+=$(tcti_detector_test_LIBS)
tcti-detector-test: tcti-detector-test.o tcti-detector.o
	$(LINK.o) -o $@ $^ $(LIBS) -lstdc++
