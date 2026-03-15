package FPSM;

import Vector::*;

typedef 32 NumLanes;
typedef TMul#(NumLanes, 8) OutputSize;

typedef struct {
    Bit#(256) pattern;
    Bit#(8)   patternLen;
    Bit#(16)  ruleId;
    Bool      valid;
} LanePattern deriving (Bits, Eq);

interface SimpleLaneIfc;
    method Action setPattern(LanePattern pat);
    method Bit#(8) checkBytes(Bit#(64) bytes);
    method Bit#(16) getRuleId();
endinterface

module mkSimpleLane(SimpleLaneIfc);
    Reg#(LanePattern) lanePattern <- mkReg(LanePattern {
        pattern: 0,
        patternLen: 0,
        ruleId: 0,
        valid: False
    });

    method Action setPattern(LanePattern pat);
        lanePattern <= pat;
    endmethod

    method Bit#(8) checkBytes(Bit#(64) bytes);
        Bit#(8) result = 0;

        if (lanePattern.valid && lanePattern.patternLen >= 4) begin
            Bit#(32) patPrefix = truncate(lanePattern.pattern);

            Bit#(32) pos0 = truncate(bytes);
            if (pos0 == patPrefix && patPrefix != 0) begin
                result[0] = 1;
            end

            Bit#(32) pos1 = truncate(bytes >> 8);
            if (pos1 == patPrefix && patPrefix != 0) begin
                result[1] = 1;
            end

            Bit#(32) pos2 = truncate(bytes >> 16);
            if (pos2 == patPrefix && patPrefix != 0) begin
                result[2] = 1;
            end

            Bit#(32) pos3 = truncate(bytes >> 24);
            if (pos3 == patPrefix && patPrefix != 0) begin
                result[3] = 1;
            end

            Bit#(32) pos4 = truncate(bytes >> 32);
            if (pos4 == patPrefix && patPrefix != 0) begin
                result[4] = 1;
            end
        end

        return result;
    endmethod

    method Bit#(16) getRuleId();
        return lanePattern.ruleId;
    endmethod
endmodule

interface SimpleFPSMIfc;
    method Action setPattern(UInt#(6) laneIdx, LanePattern pat);
    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
    method Vector#(NumLanes, Bit#(16)) getRuleIds();
endinterface

module mkSimpleFPSM(SimpleFPSMIfc);
    Vector#(NumLanes, SimpleLaneIfc) lanes <- replicateM(mkSimpleLane);

    method Action setPattern(UInt#(6) laneIdx, LanePattern pat);
        if (laneIdx < fromInteger(valueOf(NumLanes))) begin
            lanes[laneIdx].setPattern(pat);
        end
    endmethod

    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
        Vector#(OutputSize, Bool) results = replicate(False);

        Bit#(64) chunk0 = truncate(payload);
        Bit#(64) chunk1 = truncate(payload >> 64);
        Bit#(64) chunk2 = truncate(payload >> 128);
        Bit#(64) chunk3 = truncate(payload >> 192);

        for (Integer lane = 0; lane < valueOf(NumLanes); lane = lane + 1) begin
            Bit#(8) bitmap0 = lanes[lane].checkBytes(chunk0);
            Bit#(8) bitmap1 = lanes[lane].checkBytes(chunk1);
            Bit#(8) bitmap2 = lanes[lane].checkBytes(chunk2);
            Bit#(8) bitmap3 = lanes[lane].checkBytes(chunk3);
            Bit#(8) combined = bitmap0 | bitmap1 | bitmap2 | bitmap3;
            results[lane * 8] = (combined != 0);
        end

        return results;
    endmethod

    method Vector#(NumLanes, Bit#(16)) getRuleIds();
        Vector#(NumLanes, Bit#(16)) ruleIds = newVector;
        for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
            ruleIds[i] = lanes[i].getRuleId();
        end
        return ruleIds;
    endmethod
endmodule

endpackage: FPSM
