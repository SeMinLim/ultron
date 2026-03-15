#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>

#include "bdbmpcie.h"

#define PAGE_SIZE 1024

static BdbmPcie* g_pcie = nullptr;

static void writeReg(uint32_t offset, uint32_t data) {
    if (g_pcie) {
        g_pcie->userWriteWord(offset * 4, data);
    }
}

#include "../pattern_loader.h"
#define PCAP_GLOBAL_HDR_LEN 24
#define PCAP_PKT_HDR_LEN 16
#define MAX_PKT_BYTES 65536

static void store_word_be(uint8_t* base, unsigned offset, uint64_t hi, uint64_t lo)
{
	unsigned i;
	uint8_t* p = base + offset;
	for (i = 0; i < 8; i++)
		p[7 - i] = (uint8_t)(hi >> (i * 8));
	for (i = 0; i < 8; i++)
		p[15 - i] = (uint8_t)(lo >> (i * 8));
}

static void build_minimal_udp_page(uint8_t* page)
{
	memset(page, 0, PAGE_SIZE);
	store_word_be(page,  0, 0x0000000000000000ULL, 0x0000000008004500ULL);
	store_word_be(page, 16, 0x001C000000004011ULL, 0x0000c0a80101c0a8ULL);
	store_word_be(page, 32, 0x01023039D4310008ULL, 0x0000000000000000ULL);
	store_word_be(page, 48, 0x0000000000000000ULL, 0x0000000000000000ULL);
}

static uint32_t le32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t be16(const uint8_t* p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static int parse_packet(const uint8_t* buf, unsigned buf_len,
	unsigned* out_payload_offset, unsigned* out_payload_length, unsigned* out_frame_length)
{
	if (buf_len < 14 + 20)
		return -1;
	if (be16(buf + 12) != 0x0800)
		return -1;
	unsigned ip_hdr_len = (buf[14] & 0x0f) * 4;
	if (buf_len < 14u + ip_hdr_len)
		return -1;
	uint16_t ip_total = be16(buf + 16);
	unsigned frame_len = 14 + ip_total;
	if (buf_len < frame_len)
		return -1;
	uint8_t protocol = buf[14 + 9];
	unsigned l4_start = 14 + ip_hdr_len;
	unsigned l4_hdr_len = 0;
	if (protocol == 17)
		l4_hdr_len = 8;
	else if (protocol == 6) {
		if (buf_len < l4_start + 14)
			return -1;
		l4_hdr_len = (buf[l4_start + 12] >> 4) * 4;
	}
	unsigned payload_start = l4_start + l4_hdr_len;
	unsigned payload_len = (ip_total - ip_hdr_len) - l4_hdr_len;
	*out_payload_offset = payload_start;
	*out_payload_length = payload_len;
	*out_frame_length = frame_len;
	return 0;
}

static void print_hex_block(const char* label, const uint8_t* buf, unsigned len, unsigned bytes_per_line)
{
	if (label[0] != '\0')
		printf("\n%s (%u bytes)\n", label, len);
	for (unsigned i = 0; i < len; i += bytes_per_line) {
		printf("  %04x  ", i);
		for (unsigned j = 0; j < bytes_per_line && i + j < len; j++)
			printf("%02x ", buf[i + j]);
		for (unsigned j = (i + bytes_per_line < len) ? bytes_per_line : (len - i); j < bytes_per_line; j++)
			printf("   ");
		printf(" |");
		for (unsigned j = 0; j < bytes_per_line && i + j < len; j++) {
			uint8_t c = buf[i + j];
			putchar((c >= 32 && c < 127) ? c : '.');
		}
		printf("|\n");
	}
}

static unsigned feed_pcap_to_pages(FILE* fp, uint8_t* dmabuf, unsigned max_pages, unsigned* out_pages)
{
	uint8_t gbuf[PCAP_GLOBAL_HDR_LEN];
	uint8_t phdr[PCAP_PKT_HDR_LEN];
	uint8_t* pkt = (uint8_t*)malloc(MAX_PKT_BYTES);
	uint8_t page_buf[PAGE_SIZE];
	unsigned page_off = 0;
	unsigned page_idx = 0;
	unsigned pkt_count = 0;

	if (!pkt) {
		fprintf(stderr, "pcap: malloc failed\n");
		return 0;
	}
	if (fread(gbuf, 1, PCAP_GLOBAL_HDR_LEN, fp) != PCAP_GLOBAL_HDR_LEN) {
		fprintf(stderr, "pcap: short global header\n");
		free(pkt);
		return 0;
	}
	while (page_idx < max_pages && fread(phdr, 1, PCAP_PKT_HDR_LEN, fp) == PCAP_PKT_HDR_LEN) {
		uint32_t incl_len = le32(phdr + 8);
		if (incl_len > MAX_PKT_BYTES) {
			fprintf(stderr, "pcap: packet %u too large (%u)\n", pkt_count, (unsigned)incl_len);
			break;
		}
		if (fread(pkt, 1, incl_len, fp) != incl_len) {
			fprintf(stderr, "pcap: short packet %u\n", pkt_count);
			break;
		}
		pkt_count++;
		for (uint32_t i = 0; i < incl_len; i++) {
			page_buf[page_off++] = pkt[i];
			if (page_off == PAGE_SIZE) {
				memcpy(dmabuf + (size_t)page_idx * PAGE_SIZE, page_buf, PAGE_SIZE);
				page_off = 0;
				page_idx++;
				if (page_idx >= max_pages)
					break;
			}
		}
	}
	free(pkt);
	if (page_off > 0) {
		memset(page_buf + page_off, 0, PAGE_SIZE - page_off);
		memcpy(dmabuf + (size_t)page_idx * PAGE_SIZE, page_buf, PAGE_SIZE);
		page_idx++;
	}
	*out_pages = page_idx;
	return pkt_count;
}

double timespec_diff_sec(struct timespec start, struct timespec end)
{
	double t = end.tv_sec - start.tv_sec;
	t += ((double)(end.tv_nsec - start.tv_nsec) / 1000000000L);
	return t;
}

int main(int argc, char** argv)
{
	BdbmPcie* pcie = BdbmPcie::getInstance();
	g_pcie = pcie;
	uint8_t* dmabuf = (uint8_t*)pcie->dmaBuffer();

	unsigned int magic = pcie->readWord(0);
	printf("Magic: %x\n", magic);
	fflush(stdout);

	printf("\n========== Loading All Patterns from rule.txt ==========\n");
	loadAllPatterns();
	printf("\n");
	fflush(stdout);

	fflush(stdout);
	printf("streamReadCnt: %u  streamWriteCnt: %u\n",
	       (unsigned)pcie->userReadWord(0),
	       (unsigned)pcie->userReadWord(4));
	fflush(stdout);

#ifdef BLUESIM
#define OUT_PAGE 100
#define MAX_FEED_PAGES 4096
	unsigned pages_to_feed;
	unsigned pkt_count = 0;

	if (argc > 1) {
		FILE* fp = fopen(argv[1], "rb");
		if (!fp) {
			fprintf(stderr, "cannot open pcap: %s\n", argv[1]);
			return 1;
		}
		pkt_count = feed_pcap_to_pages(fp, dmabuf, MAX_FEED_PAGES, &pages_to_feed);
		fclose(fp);
		printf("pcap: %u packets -> %u pages\n", pkt_count, pages_to_feed);
		fflush(stdout);
		if (pages_to_feed == 0) {
			fprintf(stderr, "pcap: no data\n");
			return 1;
		}
	} else {
		pages_to_feed = 22;
		for (unsigned i = 0; i < pages_to_feed; i++)
			build_minimal_udp_page(dmabuf + (unsigned)i * PAGE_SIZE);
	}

	printf("Feeding %u pages:\n", pages_to_feed);
	for (unsigned i = 0; i < pages_to_feed; i++) {
		printf("  Page %u: input=%u, output=%u\n", i, i, OUT_PAGE + i);
		pcie->userWriteWord(0, i);  // Input page address
		pcie->userWriteWord(4, OUT_PAGE + i);  // Output page address for each input page
	}
	fflush(stdout);

	uint32_t readCnt = 0;
	uint32_t writeCnt = 0;
	int waitLoops = 0;
	while (writeCnt < pages_to_feed) {
		readCnt = pcie->userReadWord(0);
		writeCnt = pcie->userReadWord(4);
		waitLoops++;
		if (waitLoops % 50000 == 0 && waitLoops > 0) {
			printf("wait: read=%u write=%u (need %u)\n", readCnt, writeCnt, pages_to_feed);
			fflush(stdout);
		}
		if (waitLoops > 1000000) {
			printf("TIMEOUT: Only %u/%u pages written\n", writeCnt, pages_to_feed);
			break;
		}
		usleep(5);
	}

	printf("Done: readCnt=%u writeCnt=%u (fed %u pages)\n", readCnt, writeCnt, pages_to_feed);
	fflush(stdout);

	unsigned total_packets_found = 0;
	unsigned reassembled_packets = 0;
	uint8_t reassembly_buf[256];
	unsigned reassembly_len = 0;
	
	for (unsigned page_idx = 0; page_idx < writeCnt; page_idx++) {
		const uint8_t* out = dmabuf + (unsigned)(OUT_PAGE + page_idx) * PAGE_SIZE;
		unsigned page_off = 0;
		unsigned pkt_num = 0;

		printf("\n");
		printf("========== Output Page %u (first 256 bytes) ==========\n", OUT_PAGE + page_idx);
		print_hex_block("Raw", out, (PAGE_SIZE < 256) ? PAGE_SIZE : 256, 16);

		printf("\n---------- Packets in page %u ----------\n", OUT_PAGE + page_idx);

		if (reassembly_len > 0) {
			printf("  [Reassembly buffer has %u bytes from previous page]\n", reassembly_len);
			unsigned bytes_needed = 256 - reassembly_len;
			unsigned bytes_available = (PAGE_SIZE < bytes_needed) ? PAGE_SIZE : bytes_needed;
			memcpy(reassembly_buf + reassembly_len, out, bytes_available);
			
			unsigned payload_offset = 0;
			unsigned payload_length = 0;
			unsigned frame_length = 0;
			int ok = parse_packet(reassembly_buf, reassembly_len + bytes_available,
				&payload_offset, &payload_length, &frame_length);
			
			if (ok == 0 && frame_length <= reassembly_len + bytes_available) {
				pkt_num++;
				reassembled_packets++;
				printf("\n  Packet %u (reassembled from previous page, frame %u bytes):\n",
					pkt_num, frame_length);
				printf("    payload_offset = %u\n", payload_offset);
				printf("    payload_length = %u bytes\n", payload_length);
				if (payload_length > 0) {
					unsigned show = (payload_length <= frame_length - payload_offset) 
						? payload_length : (frame_length - payload_offset);
					print_hex_block("    Payload (hex + ASCII)", 
						reassembly_buf + payload_offset, show, 16);
				}
				unsigned consumed_from_this_page = frame_length - reassembly_len;
				page_off = consumed_from_this_page;
			}
			reassembly_len = 0;  // Clear reassembly buffer
		}
		
		while (page_off + 14 + 20 <= PAGE_SIZE) {
			unsigned payload_offset = 0;
			unsigned payload_length = 0;
			unsigned frame_length = 0;
			int ok = parse_packet(out + page_off, PAGE_SIZE - page_off,
				&payload_offset, &payload_length, &frame_length);
			if (ok != 0) {
				bool found_next = false;
				for (unsigned skip = 1; skip < PAGE_SIZE - page_off - 14 && skip < 200; skip++) {
					if (out[page_off + skip + 12] == 0x08 && out[page_off + skip + 13] == 0x00) {
						int ok2 = parse_packet(out + page_off + skip, PAGE_SIZE - page_off - skip,
							&payload_offset, &payload_length, &frame_length);
						if (ok2 == 0) {
							page_off += skip;
							found_next = true;
							break;
						}
					}
				}
				if (!found_next)
					break;
				ok = parse_packet(out + page_off, PAGE_SIZE - page_off,
					&payload_offset, &payload_length, &frame_length);
				if (ok != 0)
					break;
			}
			pkt_num++;
			unsigned payload_start_in_page = page_off + payload_offset;
			printf("\n  Packet %u (starts at byte %u, frame %u bytes):\n",
				pkt_num, page_off, frame_length);
			printf("    payload_offset = %u (L4 payload at byte %u in page)\n",
				payload_offset, payload_start_in_page);
			printf("    payload_length = %u bytes\n", payload_length);
			if (payload_length > 0) {
				unsigned avail = (payload_start_in_page < PAGE_SIZE)
					? (PAGE_SIZE - payload_start_in_page) : 0;
				unsigned show = (payload_length <= avail) ? payload_length : avail;
				if (show < payload_length)
					printf("    (showing first %u of %u in this page)\n", show, payload_length);
				print_hex_block("    Payload (hex + ASCII)", out + payload_start_in_page, show, 16);
			} else {
				printf("    Payload: (empty)\n");
			}
			page_off += frame_length;
		}

		if (page_off < PAGE_SIZE && page_idx + 1 < writeCnt) {
			reassembly_len = PAGE_SIZE - page_off;
			if (reassembly_len > 256) reassembly_len = 256;  // Cap at buffer size
			memcpy(reassembly_buf, out + page_off, reassembly_len);
			printf("  [Saved %u bytes to reassembly buffer for next page]\n", reassembly_len);
		}
		
		if (pkt_num == 0)
			printf("  (no IPv4/TCP-UDP packets parsed)\n");
		else
			printf("  Total packets in page %u: %u\n", OUT_PAGE + page_idx, pkt_num);
		total_packets_found += pkt_num;
		fflush(stdout);
	}
	
	printf("\n========================================\n");
	printf("TOTAL PACKETS IN ALL OUTPUT PAGES: %u\n", total_packets_found);
	printf("  - Reassembled across page boundaries: %u\n", reassembled_packets);
	printf("  - Unique packets (removing duplicates): %u\n", total_packets_found - reassembled_packets);
		printf("========================================\n\n");

	printf("\n========== FPSM Pattern Matching Results ==========\n");
	uint32_t fpsmResult[8];
	fpsmResult[0] = pcie->userReadWord(8);
	fpsmResult[1] = pcie->userReadWord(12);
	fpsmResult[2] = pcie->userReadWord(16);
	fpsmResult[3] = pcie->userReadWord(20);
	fpsmResult[4] = pcie->userReadWord(24);
	fpsmResult[5] = pcie->userReadWord(28);
	fpsmResult[6] = pcie->userReadWord(32);
	fpsmResult[7] = pcie->userReadWord(36);
	uint32_t fpsmChunksWithMatches = pcie->userReadWord(40);
	uint32_t fpsmTotalMatches = pcie->userReadWord(44);
	uint32_t reducedCount = pcie->userReadWord(48);
	uint32_t headerMatchCount = pcie->userReadWord(52);
	uint32_t cleanPackets = pcie->userReadWord(56);
	uint32_t nfpsmPackets = pcie->userReadWord(60);
	uint32_t totalChunks = pcie->userReadWord(64);
	
	printf("FPSM Match Result (256 bits):\n");
	printf("  [255:224] = 0x%08x  (lanes 28-31)\n", fpsmResult[7]);
	printf("  [223:192] = 0x%08x  (lanes 24-27)\n", fpsmResult[6]);
	printf("  [191:160] = 0x%08x  (lanes 20-23)\n", fpsmResult[5]);
	printf("  [159:128] = 0x%08x  (lanes 16-19)\n", fpsmResult[4]);
	printf("  [127:96]  = 0x%08x  (lanes 12-15)\n", fpsmResult[3]);
	printf("  [95:64]   = 0x%08x  (lanes 8-11)\n", fpsmResult[2]);
	printf("  [63:32]   = 0x%08x  (lanes 4-7)\n", fpsmResult[1]);
	printf("  [31:0]    = 0x%08x  (lanes 0-3)\n", fpsmResult[0]);
	
	printf("\n========== PIGASUS FULL PIPELINE RESULTS ==========\n\n");
	printf("PACKET SUMMARY:\n");
	printf("  Input Packets (PCAP):      %u\n", pkt_count);
	printf("  Output Packets (found):    %u\n", total_packets_found);
	printf("  FPSM Payload Chunks:       %u (256-bit chunks processed)\n", totalChunks);
	printf("  Clean (released):          %u\n", cleanPackets);
	printf("  Suspicious (needs NFPSM):  %u\n\n", nfpsmPackets);
	
	printf("PIPELINE STAGES:\n");
	printf("  FPSM Chunks w/ Matches:   %u (chunks that had at least one match)\n", fpsmChunksWithMatches);
	printf("  FPSM Total Matches:       %u (individual matches before reduction)\n", fpsmTotalMatches);
	printf("  Rule-Reduced Matches:     %u (after capping at 8 per chunk)\n", reducedCount);
	printf("  Header-Matched:           %u\n", headerMatchCount);
	printf("  Traffic Manager:\n");
	printf("    -> Clean:           %u\n", cleanPackets);
	printf("    -> To NFPSM:        %u\n\n", nfpsmPackets);
	
	if (reducedCount < fpsmTotalMatches) {
		printf("Rule Reduction: %u -> %u (saved %u, %.1f%%)\n", 
		       fpsmTotalMatches, reducedCount, fpsmTotalMatches - reducedCount,
		       100.0 * (fpsmTotalMatches - reducedCount) / fpsmTotalMatches);
	}
	if (headerMatchCount < reducedCount) {
		printf("Header Matching: %u -> %u (filtered %u, %.1f%%)\n",
		       reducedCount, headerMatchCount, reducedCount - headerMatchCount,
		       100.0 * (reducedCount - headerMatchCount) / reducedCount);
	}
	if (totalChunks > 0) {
		printf("Overall: %.1f%% clean packets\n",
		       100.0 * cleanPackets / totalChunks);
	}
	printf("====================================================\n");
	
	printf("\nFPSM Result Breakdown (32 lanes × 8 bytes = 256 bits):\n");
	
	for (int lane = 0; lane < 32; lane++) {
		int wordIdx = lane / 4;
		int byteInWord = lane % 4;
		uint8_t laneBits = (fpsmResult[wordIdx] >> (byteInWord * 8)) & 0xFF;
		printf("  Lane %2d (bits %3d-%3d): 0x%02x = ", 
		       lane, lane*8, lane*8+7, laneBits);
		if (laneBits == 0) {
			printf("no matches\n");
		} else {
			printf("matches at lengths:");
			for (int bit = 0; bit < 8; bit++) {
				if (laneBits & (1 << bit)) {
					printf(" %d", bit+1);
				}
			}
			printf("\n");
		}
	}
	
	printf("\n");
	fflush(stdout);
	
	return 0;
#endif

	for (uint32_t i = 0; i < 32 * 1024 / 4; i++)
		((uint32_t*)dmabuf)[i] = i;
	for (uint32_t i = 0; i < 4 * 1024 / 4; i++)
		((uint32_t*)dmabuf)[i] = i;

	int pagecnt = 4;
	struct timespec start;
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &start);
	for (int i = 0; i < pagecnt; i++) {
		pcie->userWriteWord(4, 4 + (i % 4));
		pcie->userWriteWord(0, (i % 4));
	}

	printf("----\n");
	uint32_t pages = 0;
	int sleepcnt = 0;
	while (pages < pagecnt) {
		pages = pcie->userReadWord(4);
		if (pages >= pagecnt)
			break;
		sleepcnt++;
		if (sleepcnt % 10000 == 0) {
			printf("Pages-- %d\n", pages);
			printf("!! %x\n", pcie->readWord(4));
			printf(">> %x\n", ((uint32_t*)dmabuf)[1024 / 4 * 4]);
		}
		usleep(10);
	}
	clock_gettime(CLOCK_REALTIME, &now);
	double diff = timespec_diff_sec(start, now);
	printf("Elapsed: %f\n", diff);

	printf("r %x\n", pcie->userReadWord(0));
	printf("w %x\n", pcie->userReadWord(4));

	int incorrects = 0;
	for (uint32_t i = 0; i < 1024 * 4 / 4; i++) {
		uint32_t d = ((uint32_t*)dmabuf)[i + 1024 / 4 * 4];
		if (i % 8 == 0) {
			if (d != 0xdeadbeef) {
				printf("Data incorrect! %x != %x\n", 0xdeadbeef, d);
				incorrects++;
			}
		} else {
			if (d != (uint32_t)i) {
				printf("Data incorrect! %x != %x\n", (uint32_t)i, d);
				incorrects++;
			}
		}
	}

	printf("Incorrect datas: %d\n", incorrects);
	printf("DebugCode: %x\n", pcie->readWord(4));
	return 0;
}
