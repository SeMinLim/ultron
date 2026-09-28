package SimplePacketParser;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import PcieCtrl::*;
import PacketParserTypes::*;

module mkSimplePacketParser(PacketParserIfc);

    FIFO#(DMAWord)   inQ   <- mkFIFO;
    FIFOF#(DMAWord)  outQ  <- mkFIFOF;
    FIFOF#(PacketMeta) metaQ <- mkFIFOF;

    Vector#(2, Reg#(DMAWord)) hdrBuf <- replicateM(mkRegU);
    Reg#(DMAWord) hdrBuf2   <- mkRegU;

    Reg#(Bit#(2))  fillCount  <- mkReg(0);
    Reg#(Bool)     forwarding <- mkReg(False);
    Reg#(Bit#(2))  fwdBufIdx  <- mkReg(0);
    Reg#(Bit#(16)) wordsLeft  <- mkReg(0);

    rule fillHeader(!forwarding && fillCount < 2);
        hdrBuf[fillCount] <= inQ.first;
        inQ.deq;
        fillCount <= fillCount + 1;
    endrule

    rule parseOnThirdWord(!forwarding && fillCount == 2);
        DMAWord w2 = inQ.first; inQ.deq;
        DMAWord w0 = hdrBuf[0];
        DMAWord w1 = hdrBuf[1];

        Bit#(16) totalLength = getWord16BE(w1, 0);
        Bit#(8)  protocol    = getByte128(w1, 7);
        Bit#(32) srcIp       = getWord32BE(w1, 10);
        Bit#(32) dstIp       = {getWord16BE(w1, 14), getWord16BE(w2, 0)};
        Bit#(16) srcPort     = (protocol == 1) ? 0 : getWord16BE(w2, 2);
        Bit#(16) dstPort     = (protocol == 1) ? 0 : getWord16BE(w2, 4);

        Bit#(16) l4Len;
        if (protocol == 6) begin
            Bit#(4) dataOff = getByte128(w2, 14)[7:4];
            l4Len = zeroExtend(dataOff) << 2;
        end else if (protocol == 17 || protocol == 1)
            l4Len = 8;
        else
            l4Len = 0;

        Bit#(16) payloadOffset = 34 + l4Len;
        Bit#(16) payloadLength = totalLength - 20 - l4Len;

        PacketMeta meta = PacketMeta {
            protocol:      protocol,
            srcPort:       srcPort,
            dstPort:       dstPort,
            srcIp:         srcIp,
            dstIp:         dstIp,
            totalLength:   totalLength,
            payloadOffset: payloadOffset,
            payloadLength: payloadLength
        };
        metaQ.enq(meta);

        Bit#(16) frameLen  = 14 + totalLength;
        Bit#(16) totalWds  = (frameLen + 15) >> 4;
        Bit#(16) remaining = (totalWds > 3) ? (totalWds - 3) : 0;

        hdrBuf2    <= w2;
        fwdBufIdx  <= 0;
        wordsLeft  <= remaining;
        fillCount  <= 0;
        forwarding <= True;
    endrule

    rule fwdBuffered(forwarding && fwdBufIdx < 3);
        case (fwdBufIdx)
            0: outQ.enq(hdrBuf[0]);
            1: outQ.enq(hdrBuf[1]);
            2: outQ.enq(hdrBuf2);
        endcase
        let nextIdx = fwdBufIdx + 1;
        fwdBufIdx <= nextIdx;
        if (nextIdx == 3 && wordsLeft == 0)
            forwarding <= False;
    endrule

    rule fwdStream(forwarding && fwdBufIdx == 3 && wordsLeft > 0);
        outQ.enq(inQ.first); inQ.deq;
        let rem = wordsLeft - 1;
        wordsLeft <= rem;
        if (rem == 0) forwarding <= False;
    endrule

    method Action enq(DMAWord data);
        inQ.enq(data);
    endmethod

    method Bool payloadValid   = outQ.notEmpty;
    method DMAWord payloadFirst = outQ.first;
    method Action payloadDeq;  outQ.deq;  endmethod

    method Bool metaValid       = metaQ.notEmpty;
    method PacketMeta metaFirst = metaQ.first;
    method Action metaDeq;     metaQ.deq; endmethod

endmodule

endpackage: SimplePacketParser
