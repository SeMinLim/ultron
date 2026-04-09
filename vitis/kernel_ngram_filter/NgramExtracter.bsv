package NgramExtracter;

import FIFOF::*;
import Vector::*;

typedef 64 NGramLanes;
typedef 64 NBitmapLanes;

typedef struct {
    Bit#(32) byteIdx;  // gram_value / 8
    Bit#(3)  bitIdx;   // gram_value % 8
    Bit#(32) gram;
    Bit#(32) anchor;
} NgramOut deriving (Bits, Eq, FShow);

interface NgramExtracterIfc;
    method Action putBytes(Bit#(512) word, Bit#(7) startByte, Bit#(7) count, Bool last);
    method Bool   canPut;
    method ActionValue#(Vector#(NBitmapLanes, Maybe#(NgramOut))) getGrams;
    method Bool   gramsReady;
    method Bool   idle;
    method Bool   accumulating;
endinterface

function Bit#(8) foldCase(Bit#(8) b) =
    ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;

(* synthesize *)
module mkNgramExtracter(NgramExtracterIfc);

    FIFOF#(Vector#(NBitmapLanes, Maybe#(NgramOut))) outQ <- mkSizedFIFOF(16);

    Reg#(Bit#(8))  carry0   <- mkReg(0);
    Reg#(Bit#(8))  carry1   <- mkReg(0);
    Reg#(Bool)     hasCarry <- mkReg(False);
    Reg#(Bit#(32)) basePos  <- mkReg(0);

    Reg#(Vector#(NGramLanes, Bit#(8))) batchBuf   <- mkRegU;
    Reg#(Bit#(7))                      batchCount <- mkReg(0);
    Reg#(Bool)                         batchLast  <- mkReg(False);
    Reg#(Bool)                         batchReady <- mkReg(False);

    Reg#(Vector#(NGramLanes, Maybe#(NgramOut))) stageBuf <- mkRegU;
    Reg#(Bool) stageValid <- mkReg(False);

    rule processBatch(batchReady && !stageValid);
        let ibuf = batchBuf;
        let cnt  = batchCount;
        let base = basePos;

        Vector#(NGramLanes, Maybe#(NgramOut)) result = replicate(tagged Invalid);

        for (Integer i = 0; i < valueOf(NGramLanes); i = i + 1) begin
            Bool validPos = (fromInteger(i) < cnt);
            Bool carryOk  = (fromInteger(i) >= 2) || hasCarry;
            if (validPos && carryOk) begin
                Bit#(8) b0 = foldCase((i == 0) ? carry0 :
                             (i == 1) ? carry1 :
                             ibuf[fromInteger(i - 2)]);
                Bit#(8) b1 = foldCase((i == 0) ? carry1 :
                             ibuf[fromInteger(i - 1)]);
                Bit#(8) b2 = foldCase(ibuf[fromInteger(i)]);

                Bit#(24) g24 = {b0, b1, b2};
                Bit#(32) g32 = zeroExtend(g24);

                result[fromInteger(i)] = tagged Valid (NgramOut {
                    byteIdx: g32 >> 3,
                    bitIdx:  truncate(g32),
                    gram:    g32,
                    anchor:  base + fromInteger(i) - 2
                });
            end
        end

        stageBuf   <= result;
        stageValid <= True;
        batchReady <= False;

        if (batchLast) begin
            carry0   <= 0;
            carry1   <= 0;
            hasCarry <= False;
            basePos  <= 0;
        end else if (cnt >= 2) begin
            carry0   <= ibuf[cnt - 2];
            carry1   <= ibuf[cnt - 1];
            hasCarry <= True;
            basePos  <= base + zeroExtend(cnt);
        end else begin
            carry0   <= carry1;
            carry1   <= ibuf[0];
            hasCarry <= hasCarry;
            basePos  <= base + 1;
        end
    endrule

    rule emitBatch(stageValid && outQ.notFull);
        outQ.enq(stageBuf);
        stageValid <= False;
    endrule

    method Action putBytes(Bit#(512) word, Bit#(7) startByte,
                           Bit#(7) count, Bool last) if (!batchReady);
        Vector#(NGramLanes, Bit#(8)) bytes = replicate(0);
        for (Integer i = 0; i < valueOf(NGramLanes); i = i + 1) begin
            Bit#(7) pos = startByte + fromInteger(i);
            Bit#(9) sh  = zeroExtend(pos) << 3;
            bytes[fromInteger(i)] = truncate(word >> sh);
        end
        batchBuf   <= bytes;
        batchCount <= count;
        batchLast  <= last;
        batchReady <= True;
    endmethod

    method Bool canPut = !batchReady;

    method ActionValue#(Vector#(NBitmapLanes, Maybe#(NgramOut))) getGrams
            if (outQ.notEmpty);
        let v = outQ.first;
        outQ.deq;
        return v;
    endmethod

    method Bool gramsReady   = outQ.notEmpty;
    method Bool idle         = !batchReady && !stageValid && !outQ.notEmpty;
    method Bool accumulating = batchReady || stageValid;
endmodule

endpackage
