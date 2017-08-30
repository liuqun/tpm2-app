#!/bin/bash

DATA_FILE=a_repeats_1000000_times.txt
echo "Preparing test data..."
python3 prepare_test_data.py > $DATA_FILE
echo "ls -l" $DATA_FILE
ls -l $DATA_FILE

echo
echo "Run TPM2.0 SHA1 test. (Please wait a minute)"
time { cat $DATA_FILE | ./sha1sum -localTctiTest ; }

echo
echo "Run system built-in SHA1 tools:" \``which sha1sum` $DATA_FILE \`
time { sha1sum $DATA_FILE ; }

echo
echo "Run TPM2.0 SHA256 test"
time { cat $DATA_FILE | ./sha256sum -localTctiTest ; }

echo
echo "Run system built-in SHA256 tools:" \``which sha256sum` $DATA_FILE \`
time { sha256sum $DATA_FILE ; }
