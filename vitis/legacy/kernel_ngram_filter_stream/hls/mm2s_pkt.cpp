// mm2s_pkt: replays a host-built beat image into the kernel's s_axis_pkt slave.
// Each beat is 128 bytes in memory: word0 = tdata(payload 64B); word1 carries the
// sideband -> [63:0]=tkeep, [191:64]=tuser(5-tuple), [192]=tlast.
// (Test harness; in deployment CMAC/external parser drives s_axis_pkt.)
#include <ap_int.h>
#include <hls_stream.h>
#include <ap_axi_sdata.h>

typedef ap_axiu<512, 128, 0, 0> pkt_t;   // TDATA=512, TUSER=128

void mm2s_pkt(ap_uint<512>* mem, hls::stream<pkt_t>& s, uint32_t nbeats) {
#pragma HLS INTERFACE m_axi     port=mem    offset=slave bundle=gmem
#pragma HLS INTERFACE axis      port=s
#pragma HLS INTERFACE s_axilite port=mem    bundle=control
#pragma HLS INTERFACE s_axilite port=nbeats bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control
    for (uint32_t i = 0; i < nbeats; i++) {
#pragma HLS PIPELINE II=1
        ap_uint<512> data = mem[2*i];
        ap_uint<512> meta = mem[2*i + 1];
        pkt_t x;
        x.data = data;
        x.keep = meta.range(63, 0);
        x.user = meta.range(191, 64);
        x.last = meta.range(192, 192);
        s.write(x);
    }
}
