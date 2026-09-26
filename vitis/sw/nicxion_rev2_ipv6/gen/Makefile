CC      = gcc
CFLAGS  = -Wall -O2 -std=c17
BIN     = ngram_db_gen
SRCS    = ngram_db_gen.c rule_loader.c singleton.c bitmap.c
OBJS    = $(SRCS:.c=.o)
LDLIBS  =

RULE    = ../../../../data/rule.txt
DB      = db.bin

all: $(BIN)

ngram_db_gen: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(BIN)
	./$(BIN) $(RULE) $(DB)

clean:
	rm -f $(OBJS) $(BIN) $(DB)

.PHONY: all run clean
