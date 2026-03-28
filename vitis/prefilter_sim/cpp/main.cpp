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

static void build_minimal_udp_page(uint8_t* page)
{
	static const uint8_t frame[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		0x45, 0x00,
		0x00, 0x1C,
		0x00, 0x00,
		0x00, 0x00,
		0x40, 0x11,
		0x00, 0x00,
		0xC0, 0xA8, 0x01, 0x01,
		0xC0, 0xA8, 0x01, 0x02,
		0x30, 0x39,
		0xD4, 0x31,
		0x00, 0x08,
		0x00, 0x00,
	};
	memset(page, 0, PAGE_SIZE);
	unsigned padded = (sizeof(frame) + 15) & ~15u;
	for (unsigned i = 0; i < padded; i++)
		page[i ^ 0xF] = (i < sizeof(frame)) ? frame[i] : 0;
}

static uint32_t le32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t be16(const uint8_t* p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
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

	memset(page_buf, 0, PAGE_SIZE);

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

		uint32_t padded_len = (incl_len + 15) & ~15u;
		for (uint32_t i = 0; i < padded_len; i++) {
			uint8_t byte_val = (i < incl_len) ? pkt[i] : 0;
			page_buf[page_off ^ 0xF] = byte_val;
			page_off++;
			if (page_off == PAGE_SIZE) {
				memcpy(dmabuf + (size_t)page_idx * PAGE_SIZE, page_buf, PAGE_SIZE);
				page_off = 0;
				page_idx++;
				memset(page_buf, 0, PAGE_SIZE);
				if (page_idx >= max_pages)
					break;
			}
		}
	}
	free(pkt);
	if (page_off > 0) {
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

	printf("\n========== Loading All Patterns from rule.txt ==========\n");
	loadAllPatterns();
	printf("\n");
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

	for (unsigned i = 0; i < pages_to_feed; i++) {
		pcie->userWriteWord(0, i);
		pcie->userWriteWord(4, OUT_PAGE + i);
	}
	fflush(stdout);

	uint32_t readCnt = 0;
	uint32_t writeCnt = 0;
	int waitLoops = 0;
	int allReadSettleLoops = 0;
	while (writeCnt < pages_to_feed) {
		readCnt  = pcie->userReadWord(0);
		writeCnt = pcie->userReadWord(4);
		waitLoops++;
		if (waitLoops > 1000000)
			break;
		if (readCnt >= pages_to_feed) {
			allReadSettleLoops++;
			if (allReadSettleLoops > 50000)
				break;
		}
		usleep(5);
	}

	uint32_t fpsmChunksWithMatches = pcie->userReadWord(40);
	uint32_t fpsmTotalMatches      = pcie->userReadWord(44);
	uint32_t reducedMatchBits      = pcie->userReadWord(48);
	uint32_t hdrCandidateMatches   = pcie->userReadWord(52);
	uint32_t nfpsmCleanPackets     = pcie->userReadWord(56);
	uint32_t nfpsmCPUPackets       = pcie->userReadWord(60);
	uint32_t packetCount           = pcie->userReadWord(64);
	uint32_t noFpsmClean           = pcie->userReadWord(68);
	uint32_t tm1CleanPackets       = pcie->userReadWord(72);

	uint32_t fpsmMatchedPkts = packetCount - noFpsmClean;

	printf("\n========== PIGASUS FULL PIPELINE RESULTS (per packet) ==========\n\n");
	printf("  Input packets (PCAP):                        %u\n", pkt_count);
	printf("  Packets through pipeline:        %u\n", packetCount);
	printf("\n");
	printf("  [Stage 1: FPSM]\n");
	printf("  256-bit chunks with ≥1 pattern bit:          %u\n", fpsmChunksWithMatches);
	printf("  Packets with any FPSM bit (→ Rule Reduction):%u\n", fpsmMatchedPkts);
	printf("  Packets with NO FPSM bit (early clean):      %u\n", noFpsmClean);
	printf("\n");
	printf("  [Stage 2: Header Matching\n");
	printf("  Packets with port match: %u\n", hdrCandidateMatches);
	printf("  Candidates found, but port mismatch:          %u\n", tm1CleanPackets);
	printf("\n");
	printf("  [Stage 3: (wip) NFPSM \n");
	printf("  -> CPU / Suspicious: %u\n", nfpsmCPUPackets);
	printf("  -> NFPSM-clean:       %u\n", nfpsmCleanPackets);
	printf("\n");
	uint32_t totalClean = noFpsmClean + tm1CleanPackets + nfpsmCleanPackets;
	uint32_t totalSuspicious = nfpsmCPUPackets;
	if (packetCount > 0) {
		printf("  FINAL RESULT:\n");
		printf("    Suspicious (→ CPU):  %u / %u  (%.1f%%)\n",
		       totalSuspicious, packetCount,
		       100.0 * totalSuspicious / packetCount);
		printf("    Clean (released):    %u / %u  (%.1f%%)\n",
		       totalClean, packetCount,
		       100.0 * totalClean / packetCount);
		printf("      breakdown: %u no-FPSM  +  %u TM1-clean  +  %u NFPSM-clean\n",
		       noFpsmClean, tm1CleanPackets, nfpsmCleanPackets);
	}
	printf("=================================================================\n");

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
	return 0;
}
