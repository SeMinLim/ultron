package PacketReader;

// Packet blob layout:
//   [0..64)                 64B header: magic, pkt_count, blob_bytes, reserved
//   [64..64+pktCount*32)    descriptor array: PktDesc per pkt (32B)
//   [descs_end..)           match-start payload bytes, each 64B-aligned

import FIFO::*;
import FIFOF::*;

import PacketMeta::*;

typedef enum {
    PRIdle,
    PRHeader,
    PRStart,
    PRFeedPkt,
    PRNextPkt,
    PRDone
} PRState deriving (Bits, Eq, FShow);

typedef enum {
    RKHeader,
    RKDesc,
    RKPayload
} ReadKind deriving (Bits, Eq, FShow);

typedef struct {
    ReadKind kind;
    Bit#(32) pktIdx;
    Bit#(32) bytesLeft;
} ReadRespCtx deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(32)      offset;
    Bit#(32)      length;
    PktMetaFields meta;
} PktDescEntry deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(32)      bytes;
} PayloadReadCtx deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(512)     word;
} PayloadLine deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(32)      payloadLen;
    PktMetaFields meta;
} PktMetaEntry deriving (Bits, Eq, FShow);

interface PacketReaderIfc;
    method Action   startRead(Bit#(64) pktBase, Bit#(32) pktCount);
    method Bool     pktReady;
    method Bool     pktLastByte;
    method Bit#(8)  getByte;
    method Action   advanceByte;
    method Bit#(512) getLine;
    method Bit#(6)   lineByteOffset;
    method Bit#(7)   lineValidBytes;
    method Bool      lineIsLast;
    method Action    advanceLine;
    method Bit#(32)  bytesRemaining;
    method Bool     pktDone;
    method Bool     allDone;
    method Bool     busy;
    method Bool     feedAwaitingLine;
    method Bool     descBusy;
    method Bool     startBusy;
    method Bool     startAwaitingPayload;
    method Bool     payloadRespBusy;
    method Bool     nextAfterLineReady;
    method ActionValue#(PktMetaEntry) advanceLineAndStartNextMeta;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
    method Action   readWord(Bit#(512) word);

    method Bool                        metaAvailable;
    method ActionValue#(PktMetaEntry)  nextMeta;
endinterface

module mkPacketReader(PacketReaderIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) readReqQ <- mkFIFOF;
    FIFOF#(ReadRespCtx)                 respCtxQ <- mkSizedFIFOF(128);
    FIFOF#(Bit#(512))                   rawWordQ <- mkSizedFIFOF(8);
    FIFOF#(Bit#(512))                   headerWordQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   descWordQ   <- mkSizedFIFOF(8);

    Reg#(PRState)  state    <- mkReg(PRIdle);
    Reg#(Bit#(64)) baseAddr <- mkRegU;
    Reg#(Bit#(32)) pktTotal <- mkReg(0);
    Reg#(Bit#(32)) pktIdx   <- mkReg(0);

    FIFOF#(PktDescEntry)  descFifo <- mkSizedFIFOF(128);
    FIFOF#(PktDescEntry)  prefetchDescFifo <- mkSizedFIFOF(128);
    FIFOF#(PktMetaEntry)  metaFifo <- mkSizedFIFOF(32);
    FIFOF#(PayloadLine)    payloadLineFifo <- mkSizedFIFOF(256);

    Reg#(Bit#(512)) descBuf   <- mkRegU;
    Reg#(Bit#(1))   descSub   <- mkReg(0);
    Reg#(Bit#(32))  descTotal <- mkReg(0);
    Reg#(Bit#(32))  descReqIdx <- mkReg(0);
    Reg#(Bool)      descBufValid <- mkReg(False);

    Reg#(Bool)        respActive <- mkReg(False);
    Reg#(ReadRespCtx) respCur    <- mkRegU;

    Reg#(Bit#(512)) curLine    <- mkRegU;
    Reg#(Bit#(6))   curByteOff <- mkReg(0);
    Reg#(Bit#(32))  bytesLeft  <- mkReg(0);
    Reg#(Bool)      lineValid  <- mkReg(False);

    // PktDesc layout (little-endian, packed):
    //   [0..4)   payload_offset   u32
    //   [4..8)   payload_len      u32
    //   [8]      ip_proto         u8
    //   [9]      flags            u8
    //   [10..12) src_port         u16 (little-endian host write)
    //   [12..14) dst_port         u16
    //   [14]     icmp_type        u8
    //   [15]     icmp_code        u8
    //   [16..32) reserved
    function PktDescEntry unpackDesc(Bit#(32) idx, Bit#(256) d);
        Bit#(32)  off      = d[31:0];
        Bit#(32)  len      = d[63:32];
        Bit#(8)   ipProto  = d[71:64];
        Bit#(8)   flags    = d[79:72];
        Bit#(16)  srcPort  = d[95:80];
        Bit#(16)  dstPort  = d[111:96];
        Bit#(8)   icmpType = d[119:112];
        Bit#(8)   icmpCode = d[127:120];
        return PktDescEntry {
            pktIdx: idx,
            offset: off,
            length: len,
            meta:   PktMetaFields {
                ipProto:  ipProto,
                flags:    flags,
                srcPort:  srcPort,
                dstPort:  dstPort,
                icmpType: icmpType,
                icmpCode: icmpCode
            }
        };
    endfunction

    function Bool descHasPayloadReady(PktDescEntry e);
        return (e.length > 0) &&
               payloadLineFifo.notEmpty &&
               (payloadLineFifo.first.pktIdx == e.pktIdx);
    endfunction

    function Bit#(32) min32(Bit#(32) a, Bit#(32) b);
        return (a < b) ? a : b;
    endfunction

    rule startReadResponse(!respActive && respCtxQ.notEmpty);
        respCur <= respCtxQ.first;
        respCtxQ.deq;
        respActive <= True;
    endrule

    rule routeHeaderWord(rawWordQ.notEmpty && respActive &&
                         respCur.kind == RKHeader && headerWordQ.notFull);
        let ctx = respCur;
        headerWordQ.enq(rawWordQ.first);
        rawWordQ.deq;
        if (ctx.bytesLeft <= 64)
            respActive <= False;
        else
            respCur <= ReadRespCtx { kind: ctx.kind, pktIdx: ctx.pktIdx,
                                     bytesLeft: ctx.bytesLeft - 64 };
    endrule

    rule routeDescWord(rawWordQ.notEmpty && respActive &&
                       respCur.kind == RKDesc && descWordQ.notFull);
        let ctx = respCur;
        descWordQ.enq(rawWordQ.first);
        rawWordQ.deq;
        if (ctx.bytesLeft <= 64)
            respActive <= False;
        else
            respCur <= ReadRespCtx { kind: ctx.kind, pktIdx: ctx.pktIdx,
                                     bytesLeft: ctx.bytesLeft - 64 };
    endrule

    rule routePayloadWord(rawWordQ.notEmpty && respActive &&
                          respCur.kind == RKPayload && payloadLineFifo.notFull);
        let ctx = respCur;
        payloadLineFifo.enq(PayloadLine { pktIdx: ctx.pktIdx, word: rawWordQ.first });
        rawWordQ.deq;
        if (ctx.bytesLeft <= 64)
            respActive <= False;
        else
            respCur <= ReadRespCtx { kind: ctx.kind, pktIdx: ctx.pktIdx,
                                     bytesLeft: ctx.bytesLeft - 64 };
    endrule

    rule doHeader(state == PRHeader && headerWordQ.notEmpty);
        headerWordQ.deq;
        descTotal <= 0;
        descSub   <= 0;
        descReqIdx <= 0;
        descBufValid <= False;
        respActive <= False;
        state     <= (pktTotal == 0) ? PRDone : PRStart;
    endrule

    rule issueDescRead((state == PRStart || state == PRFeedPkt || state == PRNextPkt) &&
                       descReqIdx < pktTotal &&
                       !prefetchDescFifo.notEmpty &&
                       (descReqIdx - pktIdx) < 64);
        Bit#(32) remain = pktTotal - descReqIdx;
        Bit#(32) chunkPkts = min32(remain, 16);
        Bit#(32) chunkBytes = chunkPkts << 5;
        readReqQ.enq(tuple2(baseAddr + 64 + (zeroExtend(descReqIdx) << 5),
                            zeroExtend(chunkBytes)));
        respCtxQ.enq(ReadRespCtx { kind: RKDesc, pktIdx: descReqIdx,
                                   bytesLeft: chunkBytes });
        descReqIdx <= descReqIdx + chunkPkts;
    endrule

    rule loadDescWord(!descBufValid && descWordQ.notEmpty && descTotal < pktTotal);
        descBuf <= descWordQ.first; descWordQ.deq;
        descSub <= 0;
        descBufValid <= True;
    endrule

    rule doDescsUnpack(descBufValid && descFifo.notFull && prefetchDescFifo.notFull);
        Bit#(9)   sh   = zeroExtend(descSub) << 8;
        Bit#(256) d256 = truncate(descBuf >> sh);
        let entry = unpackDesc(descTotal, d256);

        if (descTotal < pktTotal) begin
            descFifo.enq(entry);
            prefetchDescFifo.enq(entry);
            descTotal <= descTotal + 1;
        end

        Bool lastSub  = (descSub == 1);
        Bool lastDesc = (descTotal + 1 >= pktTotal);

        if (lastDesc || lastSub) begin
            descSub <= 0;
            descBufValid <= False;
        end else
            descSub <= descSub + 1;
    endrule

    rule prefetchPayload((state == PRStart || state == PRFeedPkt || state == PRNextPkt) &&
                         prefetchDescFifo.notEmpty);
        let e = prefetchDescFifo.first; prefetchDescFifo.deq;
        if (e.length > 0) begin
            readReqQ.enq(tuple2(baseAddr + zeroExtend(e.offset), zeroExtend(e.length)));
            respCtxQ.enq(ReadRespCtx { kind: RKPayload, pktIdx: e.pktIdx,
                                       bytesLeft: e.length });
        end
    endrule

    rule doStartZero((state == PRStart || state == PRNextPkt) &&
                     descFifo.notEmpty && metaFifo.notFull &&
                     descFifo.first.length == 0);
        let e = descFifo.first; descFifo.deq;
        metaFifo.enq(PktMetaEntry { pktIdx: e.pktIdx, payloadLen: e.length, meta: e.meta });
        bytesLeft <= 0;
        lineValid <= False;
        pktIdx    <= e.pktIdx + 1;
        state     <= (e.pktIdx + 1 >= pktTotal) ? PRDone : PRNextPkt;
    endrule

    rule doStartPayload((state == PRStart || state == PRNextPkt) &&
                        descFifo.notEmpty && metaFifo.notFull &&
                        descHasPayloadReady(descFifo.first));
        let e = descFifo.first; descFifo.deq;
        let l = payloadLineFifo.first; payloadLineFifo.deq;
        metaFifo.enq(PktMetaEntry { pktIdx: e.pktIdx, payloadLen: e.length, meta: e.meta });
        curLine    <= l.word;
        curByteOff <= 0;
        bytesLeft <= e.length;
        lineValid <= True;
        pktIdx    <= e.pktIdx;
        state     <= PRFeedPkt;
    endrule

    rule fetchLine(state == PRFeedPkt && !lineValid && bytesLeft > 0 &&
                   payloadLineFifo.notEmpty && payloadLineFifo.first.pktIdx == pktIdx);
        let l = payloadLineFifo.first; payloadLineFifo.deq;
        curLine    <= l.word;
        curByteOff <= 0;
        lineValid  <= True;
    endrule

    method Action startRead(Bit#(64) pktBase, Bit#(32) pktCount) if (state == PRIdle || state == PRDone);
        baseAddr <= pktBase;
        pktTotal <= pktCount;
        pktIdx   <= 0;
        lineValid <= False;
        readReqQ.enq(tuple2(pktBase, 64));
        respCtxQ.enq(ReadRespCtx { kind: RKHeader, pktIdx: 0, bytesLeft: 64 });
        state <= PRHeader;
    endmethod

    method Bool pktReady    = (state == PRFeedPkt) && lineValid && (bytesLeft > 0);
    method Bool pktLastByte = (state == PRFeedPkt) && lineValid && (bytesLeft == 1);

    method Bit#(8) getByte if (lineValid && bytesLeft > 0);
        Bit#(9) sh = zeroExtend(curByteOff) << 3;
        return truncate(curLine >> sh);
    endmethod

    method Action advanceByte if (lineValid && bytesLeft > 0);
        curByteOff <= curByteOff + 1;
        bytesLeft  <= bytesLeft - 1;
        if (curByteOff == 63 || bytesLeft == 1)
            lineValid <= False;
    endmethod

    method Bit#(512) getLine if (lineValid && bytesLeft > 0);
        return curLine;
    endmethod

    method Bit#(6) lineByteOffset if (lineValid && bytesLeft > 0);
        return 0;
    endmethod

    method Bit#(7) lineValidBytes if (lineValid && bytesLeft > 0);
        Bit#(7) avail = 7'd64 - zeroExtend(curByteOff);
        return (zeroExtend(avail) < bytesLeft) ? avail : truncate(bytesLeft);
    endmethod

    method Bool lineIsLast if (lineValid && bytesLeft > 0);
        Bit#(32) avail = zeroExtend(7'd64 - zeroExtend(curByteOff));
        return bytesLeft <= avail;
    endmethod

    method Action advanceLine if (lineValid && bytesLeft > 0);
        Bit#(32) avail   = zeroExtend(7'd64 - zeroExtend(curByteOff));
        Bit#(32) consume = (avail < bytesLeft) ? avail : bytesLeft;
        Bit#(32) nextLeft = bytesLeft - consume;
        bytesLeft <= nextLeft;
        lineValid <= False;
        if (nextLeft == 0) begin
            pktIdx <= pktIdx + 1;
            if (pktIdx + 1 >= pktTotal)
                state <= PRDone;
            else
                state <= PRNextPkt;
        end
    endmethod

    method Bool nextAfterLineReady if (lineValid && bytesLeft > 0);
        Bit#(32) avail = zeroExtend(7'd64 - zeroExtend(curByteOff));
        Bool lineLast = bytesLeft <= avail;
        Bool haveNextDesc = descFifo.notEmpty && (pktIdx + 1 < pktTotal);
        Bool nextReady = False;
        if (haveNextDesc) begin
            let e = descFifo.first;
            nextReady = (e.length == 0) || descHasPayloadReady(e);
        end
        return lineLast && nextReady;
    endmethod

    method ActionValue#(PktMetaEntry) advanceLineAndStartNextMeta
            if (lineValid && bytesLeft > 0 &&
                bytesLeft <= zeroExtend(7'd64 - zeroExtend(curByteOff)) &&
                descFifo.notEmpty &&
                pktIdx + 1 < pktTotal &&
                ((descFifo.first.length == 0) || descHasPayloadReady(descFifo.first)));
        let e = descFifo.first; descFifo.deq;
        curByteOff <= 0;
        if (e.length == 0) begin
            bytesLeft <= 0;
            lineValid <= False;
            pktIdx    <= e.pktIdx + 1;
            state     <= (e.pktIdx + 1 >= pktTotal) ? PRDone : PRNextPkt;
        end else begin
            let l = payloadLineFifo.first; payloadLineFifo.deq;
            curLine   <= l.word;
            bytesLeft <= e.length;
            lineValid <= True;
            pktIdx    <= e.pktIdx;
            state     <= PRFeedPkt;
        end
        return PktMetaEntry { pktIdx: e.pktIdx, payloadLen: e.length, meta: e.meta };
    endmethod

    method Bit#(32) bytesRemaining = bytesLeft;

    method Bool pktDone = (state == PRFeedPkt) && (bytesLeft == 0);

    method Bool allDone = (state == PRDone);

    method Bool feedAwaitingLine =
        (state == PRFeedPkt) && !lineValid && (bytesLeft > 0);

    method Bool descBusy =
        (state == PRHeader) || descBufValid || descWordQ.notEmpty ||
        (descReqIdx < pktTotal);

    method Bool startBusy =
        (state == PRStart) || (state == PRNextPkt);

    method Bool startAwaitingPayload =
        ((state == PRStart) || (state == PRNextPkt)) &&
        descFifo.notEmpty && (descFifo.first.length > 0) &&
        (!payloadLineFifo.notEmpty || (payloadLineFifo.first.pktIdx != descFifo.first.pktIdx));

    method Bool payloadRespBusy =
        respActive || respCtxQ.notEmpty || payloadLineFifo.notEmpty;

    // Excludes PRFeedPkt with bytesLeft=0 so drain stalls are not counted.
    method Bool busy =
        (state == PRHeader)      ||
        descBufValid             ||
        descWordQ.notEmpty       ||
        (descReqIdx < pktTotal)  ||
        (state == PRStart)       ||
        (state == PRNextPkt)     ||
        ((state == PRFeedPkt) && (bytesLeft > 0));

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
        let r = readReqQ.first; readReqQ.deq; return r;
    endmethod

    method Action readWord(Bit#(512) word);
        rawWordQ.enq(word);
    endmethod

    method Bool metaAvailable = metaFifo.notEmpty;

    method ActionValue#(PktMetaEntry) nextMeta;
        let m = metaFifo.first; metaFifo.deq; return m;
    endmethod

endmodule

endpackage
