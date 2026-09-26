// mm2s_db: streams the rule-DB blob from memory into the kernel's s_axis_db slave
// port (DB Master->Slave push). One run streams the whole blob; tlast on last word.
#include <ap_int.h>
#include <hls_stream.h>
#include <ap_axi_sdata.h>

typedef ap_axiu<512, 0, 0, 0> word512_t;

void mm2s_db(ap_uint<512>* mem, hls::stream<word512_t>& s, uint32_t words) {
#pragma HLS INTERFACE m_axi     port=mem    offset=slave bundle=gmem
#pragma HLS INTERFACE axis      port=s
#pragma HLS INTERFACE s_axilite port=mem    bundle=control
#pragma HLS INTERFACE s_axilite port=words  bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control
    for (uint32_t i = 0; i < words; i++) {
#pragma HLS PIPELINE II=1
        word512_t x;
        x.data = mem[i];
        x.keep = (ap_uint<64>)-1;
        x.last = (i == words - 1);
        s.write(x);
    }
}
