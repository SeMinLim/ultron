#include <iostream>
#include <fstream>
#include <vector>
#include <utility>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <algorithm>
using namespace std;

#include "xrt/xrt_bo.h"
#include <experimental/xrt_xclbin.h>
#include <experimental/xrt_ip.h>
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"

static vector<pair<uint32_t,uint32_t>> g_cfgCmds;

static void writeReg(uint32_t offset, uint32_t data) {
    g_cfgCmds.push_back({offset, data});
}

#include "../../../bluespecpcie/proj/prefilter_sim_full/pattern_loader.h"

#define PAGE_SIZE       1024
#define PCAP_GLB_HDR    24
#define PCAP_PKT_HDR    16
#define MAX_PKT_BYTES   65536

static uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static unsigned loadPcap(const char* path, uint8_t* dst, size_t dstSize,
                          size_t* outBytes)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "cannot open pcap: %s\n", path); return 0; }

    uint8_t gbuf[PCAP_GLB_HDR];
    if (fread(gbuf, 1, PCAP_GLB_HDR, fp) != PCAP_GLB_HDR) {
        fprintf(stderr, "pcap: short global header\n"); fclose(fp); return 0;
    }

    uint8_t  page_buf[PAGE_SIZE];
    uint8_t* pkt = (uint8_t*)malloc(MAX_PKT_BYTES);
    memset(page_buf, 0, PAGE_SIZE);

    size_t   totalBytes = 0;
    unsigned pktCount   = 0;
    unsigned page_off   = 0;
    uint8_t  phdr[PCAP_PKT_HDR];

    while (fread(phdr, 1, PCAP_PKT_HDR, fp) == PCAP_PKT_HDR) {
        uint32_t incl_len = le32(phdr + 8);
        if (incl_len > MAX_PKT_BYTES) break;
        if (fread(pkt, 1, incl_len, fp) != incl_len) break;
        pktCount++;

        uint32_t padded = (incl_len + 15) & ~15u;
        for (uint32_t i = 0; i < padded; i++) {
            uint8_t bval = (i < incl_len) ? pkt[i] : 0;
            page_buf[page_off ^ 0xF] = bval;
            page_off++;
            if (page_off == PAGE_SIZE) {
                if (totalBytes + PAGE_SIZE > dstSize) goto done;
                memcpy(dst + totalBytes, page_buf, PAGE_SIZE);
                totalBytes += PAGE_SIZE;
                page_off = 0;
                memset(page_buf, 0, PAGE_SIZE);
            }
        }
    }
done:
    if (page_off > 0) {
        if (totalBytes + PAGE_SIZE <= dstSize) {
            memcpy(dst + totalBytes, page_buf, PAGE_SIZE);
            totalBytes += PAGE_SIZE;
        }
    }
    free(pkt);
    fclose(fp);
    *outBytes = totalBytes;
    return pktCount;
}

struct PrefilterResult {
    uint32_t totalPackets;
    uint32_t fpsmClean;
    uint32_t tm1Suspicious;
    uint32_t tm1Clean;
    uint32_t nfpsmCPU;
    uint32_t nfpsmClean;
    uint32_t fpsmMatchWindows;
    uint32_t fpsmTotalBits;
    uint32_t reducedMatches;
    uint32_t headerHits;
};

static PrefilterResult parseResult(const uint8_t* outBuf) {
    PrefilterResult r;
    auto rd = [&](int byteOff) -> uint32_t {
        return (uint32_t)outBuf[byteOff  ]
             | ((uint32_t)outBuf[byteOff+1] << 8)
             | ((uint32_t)outBuf[byteOff+2] << 16)
             | ((uint32_t)outBuf[byteOff+3] << 24);
    };
    r.totalPackets     = rd(0);
    r.fpsmClean        = rd(4);
    r.tm1Suspicious    = rd(8);
    r.tm1Clean         = rd(12);
    r.nfpsmCPU         = rd(16);
    r.nfpsmClean       = rd(20);
    r.fpsmMatchWindows = rd(24);
    r.fpsmTotalBits    = rd(28);
    r.reducedMatches   = rd(32);
    r.headerHits       = rd(36);
    return r;
}

#define DEVICE_ID 0

int main(int argc, char** argv)
{
    string xclbinPath = "../../hw/hw/kernel.xclbin";
    const char* pcapPath = (argc > 1) ? argv[1]
        : "../../../bluespecpcie/proj/prefilter_sim_full/test.pcap";

    printf("Building config command list...\n");
    g_cfgCmds.clear();
    loadAllPatterns();
    size_t numCmds = g_cfgCmds.size();
    printf("  %zu config commands collected.\n", numCmds);

    size_t cfgBlocks = (numCmds + 7) / 8;
    printf("  cfg blocks: %zu (each 64 bytes, 8 cmd pairs)\n", cfgBlocks);

    const size_t pktBufMaxBytes = 64 * 1024 * 1024;
    vector<uint8_t> pktBuf(pktBufMaxBytes, 0);
    size_t pktBytes = 0;
    printf("Loading pcap: %s\n", pcapPath);
    unsigned pktCount = loadPcap(pcapPath, pktBuf.data(), pktBufMaxBytes, &pktBytes);
    size_t pktBlocks = pktBytes / 64;
    printf("  %u packets, %zu bytes, %zu AXI blocks\n",
           pktCount, pktBytes, pktBlocks);

    if (cfgBlocks > 0xFFFF || pktBlocks > 0xFFFF) {
        fprintf(stderr, "ERROR: block counts exceed 16-bit scalar00 field\n");
        return 1;
    }

    size_t inBufBytes  = (cfgBlocks + pktBlocks) * 64;
    size_t outBufBytes = 64;

    printf("Loading xclbin: %s\n", xclbinPath.c_str());
    xrt::device device = xrt::device(DEVICE_ID);
    xrt::uuid    uuid   = device.load_xclbin(xclbinPath);
    auto krnl = xrt::kernel(device, uuid, "kernel:{kernel_1}");

    printf("Allocating buffers: in=%zu bytes, out=%zu bytes\n",
           inBufBytes, outBufBytes);
    auto boIn  = xrt::bo(device, inBufBytes,  krnl.group_id(1));
    auto boOut = xrt::bo(device, outBufBytes, krnl.group_id(2));

    uint8_t* inMap  = boIn.map<uint8_t*>();
    uint8_t* outMap = boOut.map<uint8_t*>();
    memset(inMap,  0, inBufBytes);
    memset(outMap, 0, outBufBytes);

    printf("Writing config section to input buffer...\n");
    uint32_t* cfgWords = reinterpret_cast<uint32_t*>(inMap);
    for (size_t i = 0; i < numCmds; i++) {
        cfgWords[i * 2 + 0] = g_cfgCmds[i].second;
        cfgWords[i * 2 + 1] = g_cfgCmds[i].first;
    }

    printf("Writing packet section to input buffer...\n");
    uint8_t* pktDst = inMap + cfgBlocks * 64;
    memcpy(pktDst, pktBuf.data(), pktBytes);

    printf("Syncing input buffer to device...\n");
    boIn.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    boOut.sync(XCL_BO_SYNC_BO_TO_DEVICE);

    uint32_t scalar00 = ((uint32_t)cfgBlocks << 16) | (uint32_t)pktBlocks;
    printf("scalar00 = 0x%08X  (cfgBlocks=%zu, pktBlocks=%zu)\n",
           scalar00, cfgBlocks, pktBlocks);

    printf("Launching kernel...\n");
    auto run = krnl(scalar00, boIn, boOut);
    run.wait();
    printf("Kernel done.\n");

    boOut.sync(XCL_BO_SYNC_BO_FROM_DEVICE);
    PrefilterResult res = parseResult(outMap);

    uint32_t suspicious = res.tm1Suspicious;
    uint32_t clean      = res.fpsmClean + res.tm1Clean + res.nfpsmClean;

    printf("\n========== Pigasus MSPM Prefilter Results ==========\n");
    printf("Total valid packets          : %u\n", res.totalPackets);
    printf("\n--- Stage 1: FPSM ---\n");
    printf("  FPSM match windows         : %u\n", res.fpsmMatchWindows);
    printf("  FPSM total bit-matches     : %u\n", res.fpsmTotalBits);
    printf("  FPSM-clean (no match)      : %u\n", res.fpsmClean);
    printf("\n--- Stage 2: Rule Reduction ---\n");
    printf("  Candidates produced        : %u\n", res.reducedMatches);
    printf("\n--- Stage 3: Header Matching + TM1 ---\n");
    printf("  Header match hits          : %u\n", res.headerHits);
    printf("  TM1-suspicious (→ NFPSM)  : %u\n", res.tm1Suspicious);
    printf("  TM1-clean                 : %u\n", res.tm1Clean);
    printf("\n--- Stage 4: NFPSM + TM2 ---\n");
    printf("  NFPSM → CPU              : %u\n", res.nfpsmCPU);
    printf("  NFPSM-clean               : %u\n", res.nfpsmClean);
    printf("\n--- Final Decision ---\n");
    printf("  SUSPICIOUS (→ CPU)        : %u / %u  (%.1f%%)\n",
           suspicious, res.totalPackets,
           res.totalPackets ? 100.0 * suspicious / res.totalPackets : 0.0);
    printf("  CLEAN (released)          : %u / %u  (%.1f%%)\n",
           clean, res.totalPackets,
           res.totalPackets ? 100.0 * clean / res.totalPackets : 0.0);
    printf("====================================================\n");

    return 0;
}
