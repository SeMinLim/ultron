CC      = gcc
CFLAGS  = -Wall -O2
TARGET  = main
SRCS    = main.c rule_loader.c ngram_extract.c cuckoo_hash.c hashtable.c bitmap.c singleton.c match.c exact_match.c pcap_reader.c packet_parser.c
OBJS    = $(SRCS:.c=.o)

TEST_BM      = test_bitmap
TEST_BM_SRCS = test_bitmap.c rule_loader.c singleton.c bitmap.c cuckoo_hash.c hashtable.c
TEST_BM_OBJS = $(TEST_BM_SRCS:.c=.o)

TEST_UNIT      = test_unit
TEST_UNIT_SRCS = test_unit.c rule_loader.c ngram_extract.c singleton.c bitmap.c cuckoo_hash.c hashtable.c
TEST_UNIT_OBJS = $(TEST_UNIT_SRCS:.c=.o)

RULE    = ../../rule.txt
PCAP    = full.pcap
MAX_STAGE = 3
VERBOSE = 1

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_BM): $(TEST_BM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_UNIT): $(TEST_UNIT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET) $(RULE) $(PCAP) $(MAX_STAGE) $(VERBOSE)

run-test-bm: $(TEST_BM)
	./$(TEST_BM)

run-test-unit: $(TEST_UNIT)
	./$(TEST_UNIT)

clean:
	rm -f $(OBJS) $(TEST_BM_OBJS) $(TEST_UNIT_OBJS) $(TARGET) $(TEST_BM) $(TEST_UNIT)

.PHONY: run run-test-bm run-test-unit clean
