package FPSM;

import Vector::*;

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

    Vector#(8, Reg#(Bit#(512))) hashTables <- replicateM(mkReg(0));

    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
        Bit#(256) result = 0;
        for (Integer k = 0; k < 32; k = k + 1)
            for (Integer l = 0; l < 8; l = l + 1) begin
                Bit#(9) h = hashBytes(payload, k, l + 1);
                if (hashTables[l][h] == 1'b1)
                    result[k * 8 + l] = 1;
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
        noAction;
    endmethod

    method Bit#(8) soBitmap;
        return 8'hFF;
    endmethod

endmodule

endpackage: FPSM
