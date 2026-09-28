package NgramExtracter;

import FIFO::*;
import FIFOF::*;
import SpecialFIFOs::*;
import Vector::*;

// Front-end width, in bytes per cycle.  Sized by the bitmap lane budget: each
// lane costs one URAM per bitmap instance (3 instances), so 16 lanes = 48 URAM.
// A 512-bit packet beat is therefore fed as 64/NBitmapLanes consecutive slices
// (see KernelMain feedBeat).
typedef 16 NGramLanes;
typedef 16 NBitmapLanes;

typedef struct {
    Bit#(32) gram;
    Bit#(32) anchor;
} NgramOut deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(3) epoch;
    Bool last;
    Vector#(NBitmapLanes, Maybe#(NgramOut)) grams;
} NgramBatch deriving (Bits, Eq, FShow);

typedef struct {
    Vector#(NGramLanes, Bit#(8)) bytes;
    Bit#(7)  count;
    Bool     last;
    Bit#(3)  epoch;
} ByteBatch deriving (Bits, Eq, FShow);

interface NgramExtracterIfc;
    method Action putBytes(Bit#(512) word, Bit#(7) startByte, Bit#(7) count, Bool last, Bit#(3) epoch);
    method Bool   canPut;
    method ActionValue#(NgramBatch) getGrams;
    method Bool   gramsReady;
    method Bool   idle;
    method Bool   accumulating;
endinterface

function Bit#(8) foldCase(Bit#(8) b) =
    ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;

(* synthesize *)
module mkNgramExtracter(NgramExtracterIfc);

    FIFOF#(ByteBatch)   inQ  <- mkPipelineFIFOF;
    FIFOF#(NgramBatch)  outQ <- mkPipelineFIFOF;

    Reg#(Bit#(8))  carry0   <- mkReg(0);
    Reg#(Bit#(8))  carry1   <- mkReg(0);
    Reg#(Bool)     hasCarry <- mkReg(False);
    Reg#(Bit#(32)) basePos  <- mkReg(0);

    // Carry gates lanes 0 and 1 on the first batch to avoid anchor underflow.
    rule processBatch(outQ.notFull);
        let b    = inQ.first;
        let ibuf = b.bytes;
        let cnt  = b.count;
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

                Bit#(32) anchor = base + fromInteger(i) - 2;

                result[fromInteger(i)] = tagged Valid (NgramOut {
                    gram:   zeroExtend({b0, b1, b2}),
                    anchor: anchor
                });
            end
        end

        outQ.enq(NgramBatch { epoch: b.epoch, last: b.last, grams: result });
        inQ.deq;

        if (b.last) begin
            carry0   <= 0;
            carry1   <= 0;
            hasCarry <= False;
            basePos  <= 0;
        end else if (cnt >= 2) begin
            carry0   <= ibuf[cnt - 2];
            carry1   <= ibuf[cnt - 1];
            hasCarry <= True;
            basePos  <= base + zeroExtend(cnt);
        end else if (cnt == 1) begin
            carry0   <= carry1;
            carry1   <= ibuf[0];
            hasCarry <= hasCarry;
            basePos  <= base + 1;
        end
    endrule

    method Action putBytes(Bit#(512) word, Bit#(7) startByte,
                           Bit#(7) count, Bool last, Bit#(3) epoch) if (inQ.notFull);
        Vector#(NGramLanes, Bit#(8)) bytes = replicate(0);
        for (Integer i = 0; i < valueOf(NGramLanes); i = i + 1) begin
            Bit#(7) pos = startByte + fromInteger(i);
            Bit#(9) sh  = zeroExtend(pos) << 3;
            bytes[fromInteger(i)] = truncate(word >> sh);
        end
        inQ.enq(ByteBatch { bytes: bytes, count: count, last: last, epoch: epoch });
    endmethod

    method Bool canPut = inQ.notFull;

    method ActionValue#(NgramBatch) getGrams if (outQ.notEmpty);
        let v = outQ.first; outQ.deq;
        return v;
    endmethod

    method Bool gramsReady   = outQ.notEmpty;
    method Bool idle         = !inQ.notEmpty && !outQ.notEmpty;
    method Bool accumulating = inQ.notEmpty || outQ.notEmpty;
endmodule

endpackage
