package PacketReader;

// Reads packet blob from HBM[1] (port "pkt") and serializes bytes one per cycle.
//
// Packet blob layout:
//   [0..64)                64B header: magic, pkt_count, blob_bytes, reserved
//   [64..64+pktCount*16)   descriptor array: {raw_offset:u32, raw_len:u32, reserved:8B} per pkt
//   [descs_end..)          raw packet bytes concatenated
//
// 4 descriptors fit per 64B AXI word (each descriptor is 16B).

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

    FIFOF#(Tuple2#(Bit#(32), Bit#(32))) descFifo <- mkSizedFIFOF(256);

    Reg#(Bit#(512)) descBuf   <- mkRegU;
    Reg#(Bit#(3))   descSub   <- mkReg(0);
    Reg#(Bit#(32))  descTotal <- mkReg(0);

    Reg#(Bit#(512)) curLine   <- mkRegU;
    Reg#(Bit#(7))   lineBytes <- mkReg(0);
    Reg#(Bit#(32))  bytesLeft <- mkReg(0);
    Reg#(Bool)      lineValid <- mkReg(False);

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

    rule fetchLine(state == PRFeedPkt && !lineValid && wordQ.notEmpty);
        curLine   <= wordQ.first; wordQ.deq;
        lineBytes <= 63;
        lineValid <= True;
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

    method Bool pktReady = (state == PRFeedPkt) && lineValid && (bytesLeft > 0);

    method Bool pktLastByte = (state == PRFeedPkt) && lineValid && (bytesLeft == 1);

    method Bit#(8) getByte if (lineValid && bytesLeft > 0);
        return curLine[7:0];
    endmethod

    method Action advanceByte if (lineValid && bytesLeft > 0);
        curLine   <= curLine >> 8;
        bytesLeft <= bytesLeft - 1;
        if (lineBytes == 0)
            lineValid <= False;
        else
            lineBytes <= lineBytes - 1;
    endmethod

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
