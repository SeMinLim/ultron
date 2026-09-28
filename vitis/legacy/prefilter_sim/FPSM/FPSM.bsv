package FPSM;

import Vector::*;
import shift_or::*;

typedef 32 NumLanes;
typedef 8  BytesPerLane;
typedef TMul#(NumLanes, BytesPerLane) OutputSize;

function Bit#(8) getByte(Bit#(256) payload, Integer i);
    Integer half = (i / 16) * 128;
    Integer pos  = i % 16;
    Integer lo   = half + (15 - pos) * 8;
    return payload[lo + 7 : lo];
endfunction

function Bit#(9) hashBytes(Bit#(256) payload, Integer k, Integer len);
    Bit#(9) h = 0;
    for (Integer i = 0; i < 8; i = i + 1)
        if (i < len && k + i < 32) begin
            Bit#(9) b = zeroExtend(getByte(payload, k + i));
            Integer r = (i * 3) % 9;
            h = h ^ ((b << fromInteger(r)) | (b >> fromInteger(9 - r)));
        end
    return h;
endfunction

interface FPSMIfc;
    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
    method Action loadHTBit(Bit#(3) lenIdx, Bit#(9) hashIdx);
    method Action loadSOPattern(Bit#(64) pattern, Bit#(3) bucket, Bit#(3) lenIdx);
    method Bit#(8) soBitmap;
endinterface

(* synthesize *)
module mkFPSM(FPSMIfc);

    Vector#(8, ShiftOrIfc) soMatchers;
    soMatchers[0] <- mkShiftOr(1);
    soMatchers[1] <- mkShiftOr(2);
    soMatchers[2] <- mkShiftOr(3);
    soMatchers[3] <- mkShiftOr(4);
    soMatchers[4] <- mkShiftOr(5);
    soMatchers[5] <- mkShiftOr(6);
    soMatchers[6] <- mkShiftOr(7);
    soMatchers[7] <- mkShiftOr(8);

    Vector#(8, Reg#(Bit#(512))) hashTables <- replicateM(mkReg(0));

    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
        Bit#(256) result = 0;

        for (Integer k = 0; k < 32; k = k + 1) begin
            Bit#(64) laneWord = {
                ((k+0 < 32) ? getByte(payload, k+0) : 8'h00),
                ((k+1 < 32) ? getByte(payload, k+1) : 8'h00),
                ((k+2 < 32) ? getByte(payload, k+2) : 8'h00),
                ((k+3 < 32) ? getByte(payload, k+3) : 8'h00),
                ((k+4 < 32) ? getByte(payload, k+4) : 8'h00),
                ((k+5 < 32) ? getByte(payload, k+5) : 8'h00),
                ((k+6 < 32) ? getByte(payload, k+6) : 8'h00),
                ((k+7 < 32) ? getByte(payload, k+7) : 8'h00)
            };

            for (Integer l = 0; l < 8; l = l + 1) begin
                Bool shiftOrHit = False;
                for (Integer b = 0; b < 8; b = b + 1)
                    if (soMatchers[l].bucketHit(laneWord, fromInteger(b)))
                        shiftOrHit = True;

                Bit#(9) h = hashBytes(payload, k, l + 1);
                Bool hashHit = (hashTables[l][h] == 1'b1);

                if (shiftOrHit && hashHit)
                    result[k * 8 + l] = 1;
            end
        end

        return unpack(result);
    endmethod

    method Action loadHTBit(Bit#(3) lenIdx, Bit#(9) hashIdx);
        Bit#(512) one512 = 1;
        Bit#(512) bit_pos = one512 << hashIdx;
        case (lenIdx)
            3'd0: hashTables[0] <= hashTables[0] | bit_pos;
            3'd1: hashTables[1] <= hashTables[1] | bit_pos;
            3'd2: hashTables[2] <= hashTables[2] | bit_pos;
            3'd3: hashTables[3] <= hashTables[3] | bit_pos;
            3'd4: hashTables[4] <= hashTables[4] | bit_pos;
            3'd5: hashTables[5] <= hashTables[5] | bit_pos;
            3'd6: hashTables[6] <= hashTables[6] | bit_pos;
            3'd7: hashTables[7] <= hashTables[7] | bit_pos;
        endcase
    endmethod

    method Action loadSOPattern(Bit#(64) pattern, Bit#(3) bucket, Bit#(3) lenIdx);
        case (lenIdx)
            3'd0: soMatchers[0].insertPattern(pattern, bucket);
            3'd1: soMatchers[1].insertPattern(pattern, bucket);
            3'd2: soMatchers[2].insertPattern(pattern, bucket);
            3'd3: soMatchers[3].insertPattern(pattern, bucket);
            3'd4: soMatchers[4].insertPattern(pattern, bucket);
            3'd5: soMatchers[5].insertPattern(pattern, bucket);
            3'd6: soMatchers[6].insertPattern(pattern, bucket);
            3'd7: soMatchers[7].insertPattern(pattern, bucket);
        endcase
    endmethod

    method Bit#(8) soBitmap;
        Bit#(8) bm = 0;
        for (Integer l = 0; l < 8; l = l + 1)
            bm = bm | soMatchers[l].bucketBitmap;
        return bm;
    endmethod

endmodule

endpackage: FPSM
