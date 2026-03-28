CC      = gcc
CFLAGS  = -Wall -O2
TARGET  = main
SRCS    = main.c rule_loader.c ngram_extract.c cuckoo_hash.c hashtable.c
OBJS    = $(SRCS:.c=.o)
RULE    = rule.txt

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET) $(RULE)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: run clean
