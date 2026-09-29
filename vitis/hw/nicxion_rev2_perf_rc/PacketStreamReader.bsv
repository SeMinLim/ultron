package PacketStreamReader;

import BRAMFIFO::*;
import FIFOF::*;
import Vector::*;

import PacketMeta::*;
import AxiStream::*;

typedef 64  MaxPktBeats;   // 4 KB of payload kept per packet
typedef 128 DataBeats;     // > MaxPktBeats: see the header comment

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
    method Bit#(32)    headPktIdx;
endinterface

module mkPacketStreamReader#(AxiStreamSlaveUserIfc#(512, 128) axisIn)
                            (PacketStreamReaderIfc);

    FIFOF#(DataBeat)  dataQ <- mkSizedBRAMFIFOF(valueOf(DataBeats));
    FIFOF#(DataBeat)  outQ  <- mkFIFOF;
    FIFOF#(PktHeader) hdrQ  <- mkSizedFIFOF(16);   // one per complete packet

    Reg#(Bool)     started   <- mkReg(False);
    Reg#(Bit#(32)) inPktIdx  <- mkReg(0);
    Reg#(Bit#(7))  inBeats   <- mkReg(0);     // beats kept so far for this packet
    Reg#(Bit#(32)) inLen     <- mkReg(0);     // bytes kept so far
    Reg#(Bit#(7))  outIdx    <- mkReg(0);     // beat index within the head packet
    Reg#(Bit#(32)) outPktIdx <- mkReg(0);     // pktIdx of the head packet

    FIFOF#(Tuple4#(Bit#(512), Bit#(7), Bool, Bit#(128))) ingQ <- mkFIFOF;

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

    method Bit#(32) headPktIdx = outPktIdx;
endmodule

endpackage
