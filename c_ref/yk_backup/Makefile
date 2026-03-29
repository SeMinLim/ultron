CC      = gcc
CFLAGS  = -Wall -O2
TARGET  = main
SRCS    = main.c rule_loader.c ngram_extract.c cuckoo_hash.c hashtable.c bitmap.c singleton.c
OBJS    = $(SRCS:.c=.o)

TEST_BM      = test_bitmap
TEST_BM_SRCS = test_bitmap.c rule_loader.c singleton.c bitmap.c cuckoo_hash.c hashtable.c
TEST_BM_OBJS = $(TEST_BM_SRCS:.c=.o)
RULE    = rule.txt

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_BM): $(TEST_BM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET) $(RULE)

run-test-bm: $(TEST_BM)
	./$(TEST_BM)

clean:
	rm -f $(OBJS) $(TEST_BM_OBJS) $(TARGET) $(TEST_BM)

.PHONY: run clean
