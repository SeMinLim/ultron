package PacketReader;

// Reads packet blob from HBM[1] (port "pkt") and serializes payload bytes one
// AXI word per cycle. Host-parsed design: each descriptor is 32B and carries
// per-packet metadata (ip proto, ports, icmp type/code, flags) alongside the
// payload offset/length. Two descriptors fit per 64B AXI word.
//
// Packet blob layout:
//   [0..64)                 64B header: magic, pkt_count, blob_bytes, reserved
//   [64..64+pktCount*32)    descriptor array: PktDesc per pkt (32B)
//   [descs_end..)           match-start payload bytes, each 64B-aligned
//
// The host pre-aligns each payload so that payload byte 0 always lands at
// byte 0 of the first AXI word. lineByteOffset therefore always returns 0,
// but the method is kept for interface compatibility with ExactMatch.

import FIFO::*;
import FIFOF::*;

import PacketMeta::*;

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

typedef struct {
    Bit#(32)      offset;
    Bit#(32)      length;
    PktMetaFields meta;
} PktDescEntry deriving (Bits, Eq, FShow);

interface PacketReaderIfc;
    method Action   startRead(Bit#(64) pktBase, Bit#(32) pktCount);
    method Bool     pktReady;
    method Bool     pktLastByte;
    method Bit#(8)  getByte;
    method Action   advanceByte;
    method Bit#(512) getLine;
    method Bit#(6)   lineByteOffset;    // always 0: host aligns payload to 64B
    method Bit#(7)   lineValidBytes;
    method Bool      lineIsLast;
    method Action    advanceLine;
    method Bit#(32)  bytesRemaining;
    method Bool     pktDone;
    method Action   nextPacket;
    method Bool     allDone;
    method Bool     busy;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
    method Action   readWord(Bit#(512) word);

    // Side-channel: per-packet metadata. One entry is enqueued each time a
    // new packet's payload read is kicked off; KernelMain drains it into
    // PacketMeta before the first payload word is consumed.
    method Bool                        metaAvailable;
    method ActionValue#(PktMetaFields) nextMeta;
endinterface

module mkPacketReader(PacketReaderIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) readReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(8);

    Reg#(PRState)  state    <- mkReg(PRIdle);
    Reg#(Bit#(64)) baseAddr <- mkRegU;
    Reg#(Bit#(32)) pktTotal <- mkReg(0);
    Reg#(Bit#(32)) pktIdx   <- mkReg(0);

    FIFOF#(PktDescEntry)  descFifo <- mkSizedFIFOF(128);
    FIFOF#(PktMetaFields) metaFifo <- mkSizedFIFOF(32);

    Reg#(Bit#(512)) descBuf   <- mkRegU;
    Reg#(Bit#(1))   descSub   <- mkReg(0);     // 0 or 1: two 256-bit slots per AXI word
    Reg#(Bit#(32))  descTotal <- mkReg(0);

    Reg#(Bit#(512)) curLine    <- mkRegU;
    Reg#(Bit#(6))   curByteOff <- mkReg(0);
    Reg#(Bit#(32))  bytesLeft  <- mkReg(0);
    Reg#(Bool)      lineValid  <- mkReg(False);

    // Unpack one 256-bit slot from descBuf into a PktDescEntry. The 32B
    // PktDesc layout on the host side (little-endian, packed):
    //   [0..4)   payload_offset   u32
    //   [4..8)   payload_len      u32
    //   [8]      ip_proto         u8
    //   [9]      flags            u8
    //   [10..12) src_port         u16 (little-endian host write)
    //   [12..14) dst_port         u16
    //   [14]     icmp_type        u8
    //   [15]     icmp_code        u8
    //   [16..32) reserved
    function PktDescEntry unpackDesc(Bit#(256) d);
        Bit#(32)  off      = d[31:0];
        Bit#(32)  len      = d[63:32];
        Bit#(8)   ipProto  = d[71:64];
        Bit#(8)   flags    = d[79:72];
        Bit#(16)  srcPort  = d[95:80];
        Bit#(16)  dstPort  = d[111:96];
        Bit#(8)   icmpType = d[119:112];
        Bit#(8)   icmpCode = d[127:120];
        return PktDescEntry {
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

    rule doHeader(state == PRHeader && wordQ.notEmpty);
        wordQ.deq;
        readReqQ.enq(tuple2(baseAddr + 64, zeroExtend(pktTotal) * 32));
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
        Bit#(9)   sh   = zeroExtend(descSub) << 8;          // descSub * 256
        Bit#(256) d256 = truncate(descBuf >> sh);
        let entry = unpackDesc(d256);

        if (descTotal < pktTotal) begin
            descFifo.enq(entry);
            descTotal <= descTotal + 1;
        end

        Bool lastSub  = (descSub == 1);
        Bool lastDesc = (descTotal + 1 >= pktTotal);

        if (lastDesc)
            state <= PRStart;
        else if (lastSub) begin
            descSub <= 0;
            state   <= PRDescsFetch;
        end else
            descSub <= descSub + 1;
    endrule

    rule doStart(state == PRStart && descFifo.notEmpty && metaFifo.notFull);
        let e = descFifo.first; descFifo.deq;
        if (e.length > 0)
            readReqQ.enq(tuple2(baseAddr + zeroExtend(e.offset), zeroExtend(e.length)));
        metaFifo.enq(e.meta);
        bytesLeft <= e.length;
        lineValid <= False;
        pktIdx    <= 0;
        state     <= PRFeedPkt;
    endrule

    rule fetchLine(state == PRFeedPkt && !lineValid && wordQ.notEmpty);
        curLine    <= wordQ.first; wordQ.deq;
        curByteOff <= 0;
        lineValid  <= True;
    endrule

    rule doNextPkt(state == PRNextPkt && descFifo.notEmpty && metaFifo.notFull);
        let e = descFifo.first; descFifo.deq;
        if (e.length > 0)
            readReqQ.enq(tuple2(baseAddr + zeroExtend(e.offset), zeroExtend(e.length)));
        metaFifo.enq(e.meta);
        bytesLeft <= e.length;
        lineValid <= False;
        state     <= PRFeedPkt;
    endrule

    method Action startRead(Bit#(64) pktBase, Bit#(32) pktCount) if (state == PRIdle || state == PRDone);
        baseAddr <= pktBase;
        pktTotal <= pktCount;
        pktIdx   <= 0;
        readReqQ.enq(tuple2(pktBase, 64));
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

    // Host-aligned: payload byte 0 always lives at byte 0 of line 0, so this
    // is constant 0 for every packet. Kept only so ExactMatch's interface
    // doesn't need to change in this patch.
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

    // True iff pktReader's internal state machine is actively making
    // progress: descriptors being fetched/unpacked, a packet being kicked
    // off, or payload bytes being fed.  PRFeedPkt with bytesLeft=0 means
    // "waiting for KernelMain to retire this packet" — that idle window is
    // explicitly excluded so the metric isn't inflated by drain stalls.
    method Bool busy =
        (state == PRHeader)      ||
        (state == PRDescsFetch)  ||
        (state == PRDescsUnpack) ||
        (state == PRStart)       ||
        (state == PRNextPkt)     ||
        ((state == PRFeedPkt) && (bytesLeft > 0));

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
        let r = readReqQ.first; readReqQ.deq; return r;
    endmethod

    method Action readWord(Bit#(512) word);
        wordQ.enq(word);
    endmethod

    method Bool metaAvailable = metaFifo.notEmpty;

    method ActionValue#(PktMetaFields) nextMeta;
        let m = metaFifo.first; metaFifo.deq; return m;
    endmethod

endmodule

endpackage
