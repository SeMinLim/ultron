package NgramExtracter;

import FIFOF::*;
import Vector::*;

typedef 64 NGramLanes;
typedef 64 NBitmapLanes;

typedef struct {
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

    // Carry bytes from the previous batch needed to form cross-batch 3-grams.
    Reg#(Bit#(8))  carry0   <- mkReg(0);
    Reg#(Bit#(8))  carry1   <- mkReg(0);
    Reg#(Bool)     hasCarry <- mkReg(False);
    Reg#(Bit#(32)) basePos  <- mkReg(0);

    // One-deep batch register (reference style: no FIFO, just a ready flag).
    Reg#(Vector#(NGramLanes, Bit#(8))) batchBuf   <- mkRegU;
    Reg#(Bit#(7))                      batchCount <- mkReg(0);
    Reg#(Bool)                         batchLast  <- mkReg(False);
    Reg#(Bool)                         batchReady <- mkReg(False);

    Reg#(Vector#(NGramLanes, Maybe#(NgramOut))) stageBuf   <- mkRegU;
    Reg#(Bool)                                  stageValid <- mkReg(False);

    // Process one batch: extract up to NGramLanes 3-grams.
    // Lane i covers bytes [i-2, i-1, i] within the batch (carry bytes fill i-2, i-1
    // when i < 2).  carryOk gates lanes that need bytes from the previous batch.
    // This prevents anchor underflow: on the very first batch (hasCarry=False),
    // lanes 0 and 1 are suppressed because they would need bytes that don't exist yet.
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

                // anchor = payload position of the first byte of this 3-gram.
                // i=2 → anchor = base+0 (first gram of batch, no underflow).
                // i=0,1 with carry → anchor = base-2, base-1 (cross-batch grams).
                Bit#(32) anchor = base + fromInteger(i) - 2;

                result[fromInteger(i)] = tagged Valid (NgramOut {
                    gram:   zeroExtend({b0, b1, b2}),
                    anchor: anchor
                });
            end
        end

        stageBuf   <= result;
        stageValid <= True;
        batchReady <= False;

        // Update carry for the next batch.
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
        end else if (cnt == 1) begin
            // slide carry window by one position
            carry0   <= carry1;
            carry1   <= ibuf[0];
            hasCarry <= hasCarry;
            basePos  <= base + 1;
        end
        // cnt == 0: no bytes consumed, carry and basePos stay exactly as-is
    endrule

    rule emitBatch(stageValid && outQ.notFull);
        outQ.enq(stageBuf);
        stageValid <= False;
    endrule

    // Extract bytes from the AXI word starting at startByte into the flat batch buffer.
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
        let v = outQ.first; outQ.deq;
        return v;
    endmethod

    method Bool gramsReady   = outQ.notEmpty;
    method Bool idle         = !batchReady && !stageValid && !outQ.notEmpty;
    method Bool accumulating = batchReady || stageValid;
endmodule

endpackage
