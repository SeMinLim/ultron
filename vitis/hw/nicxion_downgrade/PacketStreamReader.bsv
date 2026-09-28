package PacketStreamReader;

import FIFOF::*;
import Vector::*;

import PacketMeta::*;
import AxiStream::*;

// tuser[127:0] layout (final-beat metadata):
//   [31:0] srcIp  [63:32] dstIp  [71:64] ipProto
//   [87:72] srcPort  [103:88] dstPort  [111:104] icmpType  [119:112] icmpCode
function PktMetaFields unpackTuser(Bit#(128) u);
    return PktMetaFields {
        srcIp:    u[31:0],
        dstIp:    u[63:32],
        ipProto:  u[71:64],
        srcPort:  u[87:72],
        dstPort:  u[103:88],
        icmpType: u[111:104],
        icmpCode: u[119:112]
    };
endfunction

// One streamed beat. first/last delimit a packet; payloadLen is the running
// byte count (final total on last); meta is valid on last.
typedef struct {
    Bit#(32)      pktIdx;
    Bit#(512)     word;
    Bit#(7)       validBytes;
    Bool          first;
    Bool          last;
    Bit#(32)      payloadLen;
    PktMetaFields meta;
} StreamBeat deriving (Bits, Eq);

interface PacketStreamReaderIfc;
    method Action      enable;
    method Bool        beatAvailable;
    method StreamBeat  beat;
    method Action      advanceBeat;
    method Bool        busy;
endinterface

module mkPacketStreamReader#(AxiStreamSlaveUserIfc#(512, 128) axisIn)
                            (PacketStreamReaderIfc);

    FIFOF#(StreamBeat) beatFifo <- mkSizedFIFOF(16);

    Reg#(Bool)     started  <- mkReg(False);
    Reg#(Bit#(32)) inPktIdx <- mkReg(0);     // pktIdx assigned per packet
    Reg#(Bit#(32)) inRunLen <- mkReg(0);     // running byte count of current packet
    Reg#(Bool)     inFirst  <- mkReg(True);  // next beat starts a new packet

    // Stream beats as they arrive. CONFORMANT to the Nixion final-beat-metadata
    // AXIS diagram: tkeep/tuser are valid ONLY on the tlast beat, so NO first-beat
    // sideband is assumed. The payload length is DERIVED by accumulating valid
    // bytes per beat (64 on full beats, popcount(tkeep) on the last) -> the true
    // total lands on the last beat. payloadLen here is the RUNNING count (bytes fed
    // through this beat); the matcher's exact end-of-payload check is deferred to
    // drain time (after tlast), so a running value up-stream is safe.
    rule ingest(started);
        let b <- axisIn.get;
        Bit#(7)  vbytes = b.last ? truncate(pack(countOnes(b.keep))) : 7'd64;
        Bit#(32) runLen = inRunLen + zeroExtend(vbytes);
        beatFifo.enq(StreamBeat {
            pktIdx: inPktIdx, word: b.data, validBytes: vbytes,
            first: inFirst, last: b.last,
            payloadLen: runLen, meta: unpackTuser(b.user) });
        if (b.last) begin
            inPktIdx <= inPktIdx + 1;
            inFirst  <= True;
            inRunLen <= 0;
        end else begin
            inFirst  <= False;
            inRunLen <= runLen;
        end
    endrule

    method Action enable;       started <= True;          endmethod
    method Bool       beatAvailable = beatFifo.notEmpty;
    method StreamBeat beat        = beatFifo.first;
    method Action     advanceBeat;  beatFifo.deq;         endmethod
    method Bool       busy        = started;
endmodule

endpackage
