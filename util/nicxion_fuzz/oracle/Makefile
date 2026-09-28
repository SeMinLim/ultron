# Links the per-packet oracle against the vendored C reference modules (cref/).
CREF_SRC ?= cref
CC       = gcc
CFLAGS   = -O2 -Wall -I$(CREF_SRC)
MODS     = rule_loader ngram_extract cuckoo_hash hashtable bitmap singleton match \
           exact_match port_offset_matcher priority packet_parser pcap_reader \
           xor_filter bloomfilter
SRCS     = $(addprefix $(CREF_SRC)/,$(addsuffix .c,$(MODS)))

pm_oracle: pm_oracle.c $(SRCS)
	$(CC) $(CFLAGS) -o $@ pm_oracle.c $(SRCS) -lm

clean:
	rm -f pm_oracle
.PHONY: clean
