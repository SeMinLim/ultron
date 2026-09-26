package PacketStreamReader;

// AXI4-Stream packet input — store-and-forward per packet, deadlock-free.
//
// Final-beat metadata model (Nixion): tdata streams payload beats; tuser and
// the final tkeep arrive only on the tlast beat.  A packet is exposed to the
// matcher only once its tlast has been received, so its 5-tuple and length are
// known BEFORE its first byte is fed.  No match result ever has to wait for its
// own packet's metadata.
//
// Why not stream (the previous design): hits had to be held until the packet
// finished feeding (pomHoldQ).  A packet producing more hits than that queue
// holds stalled the matcher, which stalled the feed, so the packet never
// finished -- a permanent deadlock, found on the chip by nicxion_fuzz (one
// packet with ~1,900 exact-match candidates).
//
// Why this buffer cannot deadlock (the store-and-forward reader before the
// streaming one did, see kernel_neo_stream_opti_20260703_11/fix.md): that one
// could fill up with a single incomplete packet, whose metadata never arrived.
// Here each packet keeps at most MaxPktBeats beats (the ExactMatch payload
// table holds 64 lines per epoch, so bytes beyond 4 KB were never matchable);
// further beats are consumed and discarded, never blocking.  The buffer holds
// more than one packet's worth (DataBeats > MaxPktBeats), so whenever it is
// full at least one COMPLETE packet is inside, and that packet can always be
// fed -> ingest always makes progress.

import BRAMFIFO::*;
import FIFOF::*;
import Vector::*;

import PacketMeta::*;
import AxiStream::*;

typedef 64  MaxPktBeats;   // 4 KB of payload kept per packet
typedef 128 DataBeats;     // > MaxPktBeats: see the header comment

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

// One beat as seen by the matcher.  first/last delimit a packet; payloadLen
// (bytes kept) and meta are FINAL and valid on every beat.
typedef struct {
    Bit#(32)      pktIdx;
    Bit#(512)     word;
    Bit#(7)       validBytes;
    Bool          first;
    Bool          last;
    Bit#(32)      payloadLen;
    PktMetaFields meta;
} StreamBeat deriving (Bits, Eq);

typedef struct {
    Bit#(512) word;
    Bit#(7)   validBytes;
} DataBeat deriving (Bits, Eq);

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(32)      keptLen;     // payload bytes kept (== total when <= 4 KB)
    Bit#(7)       keptBeats;   // 1..MaxPktBeats
    PktMetaFields meta;
} PktHeader deriving (Bits, Eq);

interface PacketStreamReaderIfc;
    method Action      enable;
    method Bool        beatAvailable;
    method StreamBeat  beat;
    method Action      advanceBeat;
    method Bool        busy;
    // pktIdx of the head packet as a plain register (no implicit condition):
    // equal to beat.pktIdx whenever a beat is available.  Lets KernelMain
    // precompute the admission check a cycle early.
    method Bit#(32)    headPktIdx;
endinterface

module mkPacketStreamReader#(AxiStreamSlaveUserIfc#(512, 128) axisIn)
                            (PacketStreamReaderIfc);

    FIFOF#(DataBeat)  dataQ <- mkSizedBRAMFIFOF(valueOf(DataBeats));
    // Registered stage after the BRAM FIFO (its read is unregistered): keeps the
    // 519-bit BRAM output off the feed path at 250 MHz.  Order is preserved and
    // total capacity only grows, so the no-deadlock argument above still holds.
    FIFOF#(DataBeat)  outQ  <- mkFIFOF;
    FIFOF#(PktHeader) hdrQ  <- mkSizedFIFOF(16);   // one per complete packet

    Reg#(Bool)     started   <- mkReg(False);
    Reg#(Bit#(32)) inPktIdx  <- mkReg(0);
    Reg#(Bit#(7))  inBeats   <- mkReg(0);     // beats kept so far for this packet
    Reg#(Bit#(32)) inLen     <- mkReg(0);     // bytes kept so far
    Reg#(Bit#(7))  outIdx    <- mkReg(0);     // beat index within the head packet
    Reg#(Bit#(32)) outPktIdx <- mkReg(0);     // pktIdx of the head packet

    // AXIS beat + its byte count, registered before the per-packet bookkeeping:
    // the 64-bit tkeep popcount and the length/limit logic no longer share a
    // cycle (250 MHz).
    FIFOF#(Tuple4#(Bit#(512), Bit#(7), Bool, Bit#(128))) ingQ <- mkFIFOF;

    // Payload length comes from the beats themselves: 64 bytes per full beat,
    // popcount(tkeep) on the last (tkeep is only valid there).
    rule ingestIn(started);
        let b <- axisIn.get;
        Bit#(7) vbytes = b.last ? truncate(pack(countOnes(b.keep))) : 7'd64;
        ingQ.enq(tuple4(b.data, vbytes, b.last, b.user));
    endrule

    rule ingest;
        match { .data, .vbytes, .isLast, .user } = ingQ.first; ingQ.deq;
        Bool    keep   = inBeats < fromInteger(valueOf(MaxPktBeats));
        if (keep) dataQ.enq(DataBeat { word: data, validBytes: vbytes });
        Bit#(7)  beats = keep ? inBeats + 1 : inBeats;
        Bit#(32) len   = keep ? inLen + zeroExtend(vbytes) : inLen;
        if (isLast) begin
            hdrQ.enq(PktHeader { pktIdx: inPktIdx, keptLen: len, keptBeats: beats,
                                 meta: unpackTuser(user) });
            inPktIdx <= inPktIdx + 1;
            inBeats  <= 0;
            inLen    <= 0;
        end else begin
            inBeats  <= beats;
            inLen    <= len;
        end
    endrule

    rule stageOut;
        outQ.enq(dataQ.first);
        dataQ.deq;
    endrule

    // The head of outQ belongs to the oldest packet; it is complete exactly
    // when its header is in hdrQ (packets complete in arrival order).
    method Action enable;       started <= True;          endmethod
    method Bool beatAvailable = outQ.notEmpty && hdrQ.notEmpty;

    method StreamBeat beat;
        let h = hdrQ.first;
        let d = outQ.first;
        return StreamBeat {
            pktIdx: h.pktIdx, word: d.word, validBytes: d.validBytes,
            first: outIdx == 0, last: outIdx + 1 == h.keptBeats,
            payloadLen: h.keptLen, meta: h.meta };
    endmethod

    method Action advanceBeat;
        outQ.deq;
        if (outIdx + 1 == hdrQ.first.keptBeats) begin
            hdrQ.deq;
            outIdx    <= 0;
            outPktIdx <= outPktIdx + 1;
        end else
            outIdx <= outIdx + 1;
    endmethod

    method Bool busy = started;
    method Bit#(32) headPktIdx = outPktIdx;
endmodule

endpackage
