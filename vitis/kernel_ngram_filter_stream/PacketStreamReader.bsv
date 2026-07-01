package PacketStreamReader;

// Decoupled AXI4-Stream packet input — streams each beat immediately.
// Prior whole-packet buffering caused a metadata-coupling DEADLOCK under line-rate;
// skid FIFO + per-beat epoch allocation makes overload plain backpressure instead.

import FIFOF::*;
import Vector::*;

import PacketMeta::*;
import PacketReader::*;
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
    // Legacy stubs (telemetry rules in KernelMain still reference these).
    method Bool        pktReady;
    method Bool        pktDone;
    method Bool        feedAwaitingLine;
    method Bool        allDone;
    method Bool        descBusy;
    method Bool        startBusy;
    method Bool        startAwaitingPayload;
    method Bool        payloadRespBusy;
endinterface

module mkPacketStreamReader#(AxiStreamSlaveUserIfc#(512, 128) axisIn)
                            (PacketStreamReaderIfc);

    // Small skid FIFO — the matcher always drains it, so it never fills enough
    // to deadlock; it only provides a few cycles of elasticity.
    FIFOF#(StreamBeat) beatFifo <- mkSizedFIFOF(16);

    Reg#(Bool)     started  <- mkReg(False);
    Reg#(Bit#(32)) inPktIdx <- mkReg(0);
    Reg#(Bit#(32)) inPlen   <- mkReg(0);
    Reg#(Bool)     inFirst  <- mkReg(True);

    // Full length on every beat: from tuser[31:0] of first beat (avoids false rejects
    // near EOF from mid-packet running lengths); single-beat packets use validBytes.
    rule ingest(started);
        let b <- axisIn.get;
        Bit#(7)  vbytes = b.last ? truncate(pack(countOnes(b.keep))) : 7'd64;
        Bit#(32) fullLen = inFirst ? (b.last ? zeroExtend(vbytes) : b.user[31:0])
                                   : inPlen;
        beatFifo.enq(StreamBeat {
            pktIdx: inPktIdx, word: b.data, validBytes: vbytes,
            first: inFirst, last: b.last,
            payloadLen: fullLen, meta: unpackTuser(b.user) });
        if (inFirst && !b.last) inPlen <= b.user[31:0];
        if (b.last) begin
            inPktIdx <= inPktIdx + 1;
            inFirst  <= True;
        end else begin
            inFirst  <= False;
        end
    endrule

    method Action enable;       started <= True;          endmethod
    method Bool       beatAvailable = beatFifo.notEmpty;
    method StreamBeat beat        = beatFifo.first;
    method Action     advanceBeat;  beatFifo.deq;         endmethod
    method Bool       busy        = started;

    // Legacy stubs.
    method Bool pktReady             = beatFifo.notEmpty;
    method Bool pktDone              = False;
    method Bool feedAwaitingLine     = started && !beatFifo.notEmpty;
    method Bool allDone              = False;
    method Bool descBusy             = False;
    method Bool startBusy            = False;
    method Bool startAwaitingPayload = False;
    method Bool payloadRespBusy      = False;
endmodule

endpackage
