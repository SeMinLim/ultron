package PacketReader;

// Reads packet blob from HBM[1] (port "pkt") and serializes bytes one per cycle.
//
// Packet blob layout:
//   [0..64)                64B header: magic, pkt_count, blob_bytes, reserved
//   [64..64+pktCount*16)   descriptor array: {raw_offset:u32, raw_len:u32, reserved:8B} per pkt
//   [descs_end..)          raw packet bytes concatenated
//
// 4 descriptors fit per 64B AXI word (each descriptor is 16B).
//
// curLine is NOT shifted as bytes are consumed.  Instead, curByteOff tracks the
// current read position within the line (0..63).  This lets callers inspect the
// full, unmodified AXI word (getLine) alongside the byte offset (lineByteOffset),
// which is used by ExactMatch as pay_off.

import FIFO::*;
import FIFOF::*;

typedef enum {
    PRIdle,
    PRHeader,
    PRDescsFetch,
    PRDescsUnpack,
    PRStart,
    PRFeedPkt,
    PRNextPkt,
    PRDone
} PRState deriving (Bits, Eq, FShow);

interface PacketReaderIfc;
    method Action   startRead(Bit#(64) pktBase, Bit#(32) pktCount);
    method Bool     pktReady;
    method Bool     pktLastByte;
    method Bit#(8)  getByte;
    method Action   advanceByte;
    method Bit#(512) getLine;
    method Bit#(6)   lineByteOffset;    // byte index of current read position in curLine
    method Bit#(7)   lineValidBytes;    // valid payload bytes remaining in this line
    method Bool      lineIsLast;        // true if this line holds the last payload bytes
    method Action    advanceLine;
    method Bit#(32)  bytesRemaining;    // packet bytes not yet consumed (payload length proxy)
    method Bool     pktDone;
    method Action   nextPacket;
    method Bool     allDone;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
    method Action   readWord(Bit#(512) word);
endinterface

module mkPacketReader(PacketReaderIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) readReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(8);

    Reg#(PRState)  state    <- mkReg(PRIdle);
    Reg#(Bit#(64)) baseAddr <- mkRegU;
    Reg#(Bit#(32)) pktTotal <- mkReg(0);
    Reg#(Bit#(32)) pktIdx   <- mkReg(0);

    FIFOF#(Tuple2#(Bit#(32), Bit#(32))) descFifo <- mkSizedFIFOF(32768);

    Reg#(Bit#(512)) descBuf   <- mkRegU;
    Reg#(Bit#(3))   descSub   <- mkReg(0);
    Reg#(Bit#(32))  descTotal <- mkReg(0);

    Reg#(Bit#(512)) curLine    <- mkRegU;
    Reg#(Bit#(6))   curByteOff <- mkReg(0);   // read position within curLine (0 = byte 0)
    Reg#(Bit#(32))  bytesLeft  <- mkReg(0);   // packet bytes not yet consumed
    Reg#(Bool)      lineValid  <- mkReg(False);

    rule doHeader(state == PRHeader && wordQ.notEmpty);
        wordQ.deq;
        readReqQ.enq(tuple2(baseAddr + 64, zeroExtend(pktTotal) * 16));
        descTotal <= 0;
        descSub   <= 0;
        state     <= PRDescsFetch;
    endrule

    rule doDescsFetch(state == PRDescsFetch && wordQ.notEmpty && descTotal < pktTotal);
        descBuf <= wordQ.first; wordQ.deq;
        descSub <= 0;
        state   <= PRDescsUnpack;
    endrule

    rule doDescsUnpack(state == PRDescsUnpack && descFifo.notFull);
        Bit#(9)   sh    = zeroExtend(descSub) << 7;   // descSub * 128 bits
        Bit#(128) d128  = truncate(descBuf >> sh);
        Bit#(32)  dOff  = d128[31:0];
        Bit#(32)  dLen  = d128[63:32];

        if (descTotal < pktTotal) begin
            descFifo.enq(tuple2(dOff, dLen));
            descTotal <= descTotal + 1;
        end

        Bool lastSub  = (descSub == 3);
        Bool lastDesc = (descTotal + 1 >= pktTotal);

        if (lastDesc)
            state <= PRStart;
        else if (lastSub) begin
            descSub <= 0;
            state   <= PRDescsFetch;
        end else
            descSub <= descSub + 1;
    endrule

    rule doStart(state == PRStart && descFifo.notEmpty);
        let {dOff, dLen} = descFifo.first; descFifo.deq;
        readReqQ.enq(tuple2(baseAddr + zeroExtend(dOff), zeroExtend(dLen)));
        bytesLeft <= dLen;
        lineValid <= False;
        pktIdx    <= 0;
        state     <= PRFeedPkt;
    endrule

    // Fetch next AXI word into curLine; reset byte offset to 0.
    rule fetchLine(state == PRFeedPkt && !lineValid && wordQ.notEmpty);
        curLine    <= wordQ.first; wordQ.deq;
        curByteOff <= 0;
        lineValid  <= True;
    endrule

    rule doNextPkt(state == PRNextPkt && descFifo.notEmpty);
        let {dOff, dLen} = descFifo.first; descFifo.deq;
        readReqQ.enq(tuple2(baseAddr + zeroExtend(dOff), zeroExtend(dLen)));
        bytesLeft <= dLen;
        lineValid <= False;
        state     <= PRFeedPkt;
    endrule

    method Action startRead(Bit#(64) pktBase, Bit#(32) pktCount) if (state == PRIdle);
        baseAddr <= pktBase;
        pktTotal <= pktCount;
        readReqQ.enq(tuple2(pktBase, 64));
        state <= PRHeader;
    endmethod

    method Bool pktReady    = (state == PRFeedPkt) && lineValid && (bytesLeft > 0);
    method Bool pktLastByte = (state == PRFeedPkt) && lineValid && (bytesLeft == 1);

    // Extract the byte at curByteOff from the unshifted curLine.
    method Bit#(8) getByte if (lineValid && bytesLeft > 0);
        Bit#(9) sh = zeroExtend(curByteOff) << 3;
        return truncate(curLine >> sh);
    endmethod

    // Advance one byte: move curByteOff forward; invalidate line at word boundary or
    // last packet byte so fetchLine picks up the next word.
    method Action advanceByte if (lineValid && bytesLeft > 0);
        curByteOff <= curByteOff + 1;
        bytesLeft  <= bytesLeft - 1;
        if (curByteOff == 63 || bytesLeft == 1)
            lineValid <= False;
    endmethod

    // Full unshifted AXI word — callers use lineByteOffset to find where their
    // data starts within this word.
    method Bit#(512) getLine if (lineValid && bytesLeft > 0);
        return curLine;
    endmethod

    // Byte offset of the current read position within curLine.
    // For the first payload word this equals pay_off for ExactMatch.
    method Bit#(6) lineByteOffset if (lineValid && bytesLeft > 0);
        return curByteOff;
    endmethod

    // How many bytes of this line belong to the current packet.
    method Bit#(7) lineValidBytes if (lineValid && bytesLeft > 0);
        Bit#(7) avail = 7'd64 - zeroExtend(curByteOff);
        return (zeroExtend(avail) < bytesLeft) ? avail : truncate(bytesLeft);
    endmethod

    // True when all remaining packet bytes are in this line.
    method Bool lineIsLast if (lineValid && bytesLeft > 0);
        Bit#(32) avail = zeroExtend(7'd64 - zeroExtend(curByteOff));
        return bytesLeft <= avail;
    endmethod

    // Consume the rest of this line and mark it invalid so fetchLine loads the next.
    method Action advanceLine if (lineValid && bytesLeft > 0);
        Bit#(32) avail   = zeroExtend(7'd64 - zeroExtend(curByteOff));
        Bit#(32) consume = (avail < bytesLeft) ? avail : bytesLeft;
        bytesLeft <= bytesLeft - consume;
        lineValid <= False;
    endmethod

    method Bit#(32) bytesRemaining = bytesLeft;

    method Bool pktDone = (state == PRFeedPkt) && (bytesLeft == 0);

    method Action nextPacket if (state == PRFeedPkt && bytesLeft == 0);
        pktIdx <= pktIdx + 1;
        if (pktIdx + 1 >= pktTotal)
            state <= PRDone;
        else
            state <= PRNextPkt;
    endmethod

    method Bool allDone = (state == PRDone);

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
        let r = readReqQ.first; readReqQ.deq; return r;
    endmethod

    method Action readWord(Bit#(512) word);
        wordQ.enq(word);
    endmethod

endmodule

endpackage
