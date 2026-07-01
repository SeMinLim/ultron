// s2mm: drains the kernel's m_axis_result stream (32-bit {match,ruleId} beats,
// one per packet, tlast=1 each) into memory so the host can read results.
// (Test-harness only; the real consumer is the company's code / CMAC path.)
#include <ap_int.h>
#include <hls_stream.h>
#include <ap_axi_sdata.h>

typedef ap_axiu<32, 0, 0, 0> res_t;

void s2mm(ap_uint<32>* mem, hls::stream<res_t>& s, uint32_t n) {
#pragma HLS INTERFACE m_axi     port=mem    offset=slave bundle=gmem
#pragma HLS INTERFACE axis      port=s
#pragma HLS INTERFACE s_axilite port=mem    bundle=control
#pragma HLS INTERFACE s_axilite port=n      bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control
    for (uint32_t i = 0; i < n; i++) {
#pragma HLS PIPELINE II=1
        res_t x = s.read();
        mem[i] = x.data;
    }
}
