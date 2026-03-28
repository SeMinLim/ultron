

package RuleReduction;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import RegFile::*;
import PacketParserTypes::*;

typedef 256 InputWidth;

function Bit#(32) countMatches(Vector#(InputWidth, Bool) fpsmBits);
    Bit#(32) total = 0;
    for (Integer i = 0; i < valueOf(InputWidth); i = i + 1)
        if (fpsmBits[i]) total = total + 1;
    return total;
endfunction

function Bit#(32) reduceMatchCount(Vector#(InputWidth, Bool) fpsmBits);
    Bit#(32) count = countMatches(fpsmBits);
    return (count > 8) ? 8 : count;
endfunction

function Bit#(8) getDynByte(Bit#(256) payload, Bit#(5) bytePos);
    Bit#(4) pos_half = bytePos[3:0];
    Bit#(4) rev_pos  = 4'hF - pos_half;
    Bit#(8) bit_lo   = {bytePos[4], rev_pos, 3'b0};
    return truncate(payload >> bit_lo);
endfunction

function Bit#(64) extractWindow(Bit#(256) payload, Bit#(5) lane, Bit#(3) lenIdx);
    Bit#(64) window = 0;
    for (Integer i = 0; i < 8; i = i + 1) begin
        Bit#(6) bytePos6 = {1'b0, lane} + fromInteger(i);
        Bool inRange = (fromInteger(i) <= lenIdx) && (bytePos6 < 32);
        Bit#(8) b = inRange ? getDynByte(payload, truncate(bytePos6)) : 8'h00;
        window = window | (zeroExtend(b) << fromInteger((7 - i) * 8));
    end
    return window;
endfunction

typedef struct {
    Bool     valid;
    Bit#(64) pattern;
    Bit#(16) ruleId;
} CuckooEntry deriving (Bits, Eq);

function Bit#(9) ckHash1(Bit#(64) p);
    return p[8:0] ^ p[17:9] ^ p[26:18] ^ p[35:27] ^ p[44:36] ^ p[53:45] ^ p[62:54];
endfunction

function Bit#(9) rotL9(Bit#(9) b, Integer r);
    case (r)
        0: return b;
        3: return {b[5:0], b[8:6]};
        6: return {b[2:0], b[8:3]};
        default: return b;
    endcase
endfunction

function Bit#(9) ckHash2(Bit#(64) p);
    return rotL9(zeroExtend(p[63:56]), 0)
         ^ rotL9(zeroExtend(p[55:48]), 3)
         ^ rotL9(zeroExtend(p[47:40]), 6)
         ^ rotL9(zeroExtend(p[39:32]), 0)
         ^ rotL9(zeroExtend(p[31:24]), 3)
         ^ rotL9(zeroExtend(p[23:16]), 6)
         ^ rotL9(zeroExtend(p[15: 8]), 0)
         ^ rotL9(zeroExtend(p[ 7: 0]), 3);
endfunction

typedef 8 MaxCandidates;

interface RuleReductionIfc;
    method Action putWindow(Bit#(256) fpsmBits, Bit#(256) payload,
                            PacketMeta meta, Bool isLast);
    method Bool   outValid();
    method Vector#(MaxCandidates, Maybe#(Bit#(16))) outRuleIds();
    method PacketMeta outMeta();
    method Action outDeq();

    method Action loadCuckooEntry(Bit#(1) tableIdx, Bit#(3) lenIdx, Bit#(9) hashIdx,
                                   Bit#(64) pattern, Bit#(16) ruleId);
endinterface

module mkRuleReduction(RuleReductionIfc);

    RegFile#(Bit#(12), CuckooEntry) ckTable1 <- mkRegFileFull();
    RegFile#(Bit#(12), CuckooEntry) ckTable2 <- mkRegFileFull();

    Reg#(Bool)     ckInitDone <- mkReg(False);
    Reg#(Bit#(13)) ckInitIdx  <- mkReg(0);

    rule ckInit(!ckInitDone);
        CuckooEntry empty = CuckooEntry { valid: False, pattern: 0, ruleId: 0 };
        ckTable1.upd(truncate(ckInitIdx), empty);
        ckTable2.upd(truncate(ckInitIdx), empty);
        if (ckInitIdx == 13'h0FFF) ckInitDone <= True;
        else ckInitIdx <= ckInitIdx + 1;
    endrule

    FIFO#(Tuple4#(Bit#(256), Bit#(256), PacketMeta, Bool)) inQ <- mkFIFO;
    FIFOF#(Tuple2#(Vector#(MaxCandidates, Maybe#(Bit#(16))), PacketMeta)) outQ
        <- mkFIFOF;

    Reg#(Bool)       scanning     <- mkReg(False);
    Reg#(Bit#(9))    scanPos      <- mkReg(0);
    Reg#(Bit#(256))  scanBits     <- mkReg(0);
    Reg#(Bit#(256))  savedPayload <- mkRegU;
    Reg#(PacketMeta) savedMeta    <- mkRegU;
    Reg#(Bool)       savedIsLast  <- mkReg(False);
    Reg#(Bit#(4))    candCount    <- mkReg(0);

    Reg#(Vector#(MaxCandidates, Maybe#(Bit#(16)))) cands
        <- mkReg(replicate(tagged Invalid));

    rule startScan(!scanning && ckInitDone);
        match {.bits, .payload, .meta, .isLast} = inQ.first;
        inQ.deq;

        if (bits == 0) begin
            if (isLast) begin
                outQ.enq(tuple2(cands, meta));
                cands     <= replicate(tagged Invalid);
                candCount <= 0;
            end
        end else begin
            scanBits     <= bits;
            savedPayload <= payload;
            savedMeta    <= meta;
            savedIsLast  <= isLast;
            scanPos      <= 0;
            scanning     <= True;
        end
    endrule

    rule doScan(scanning);
        Bit#(8) pos    = truncate(scanPos);
        Bit#(5) lane   = pos[7:3];
        Bit#(3) lenIdx = pos[2:0];

        Vector#(MaxCandidates, Maybe#(Bit#(16))) newCands = cands;
        Bit#(4) newCount = candCount;

        if (scanBits[pos] == 1 &&
            candCount < fromInteger(valueOf(MaxCandidates))) begin

            Bit#(64) window = extractWindow(savedPayload, lane, lenIdx);
            Bit#(9)  h1     = ckHash1(window);
            Bit#(9)  h2     = ckHash2(window);

            CuckooEntry e1 = ckTable1.sub({lenIdx, h1});
            CuckooEntry e2 = ckTable2.sub({lenIdx, h2});

            for (Integer t = 0; t < 2; t = t + 1) begin
                CuckooEntry e = (t == 0) ? e1 : e2;
                if (e.valid && newCount < fromInteger(valueOf(MaxCandidates))) begin
                    Bool dup = False;
                    for (Integer j = 0; j < valueOf(MaxCandidates); j = j + 1)
                        if (cands[j] matches tagged Valid .rid &&& rid == e.ruleId)
                            dup = True;
                    if (!dup) begin
                        newCands[newCount] = tagged Valid e.ruleId;
                        newCount = newCount + 1;
                    end
                end
            end
        end

        Bool done = (scanPos == 255) ||
                    (newCount == fromInteger(valueOf(MaxCandidates)));
        if (done) begin
            if (savedIsLast) begin
                outQ.enq(tuple2(newCands, savedMeta));
                cands     <= replicate(tagged Invalid);
                candCount <= 0;
            end else begin
                cands     <= newCands;
                candCount <= newCount;
            end
            scanning <= False;
        end else begin
            cands     <= newCands;
            candCount <= newCount;
            scanPos   <= scanPos + 1;
        end
    endrule

    method Action putWindow(Bit#(256) fpsmBits, Bit#(256) payload,
                            PacketMeta meta, Bool isLast);
        inQ.enq(tuple4(fpsmBits, payload, meta, isLast));
    endmethod

    method Bool outValid() = outQ.notEmpty;

    method Vector#(MaxCandidates, Maybe#(Bit#(16))) outRuleIds();
        return tpl_1(outQ.first);
    endmethod

    method PacketMeta outMeta();
        return tpl_2(outQ.first);
    endmethod

    method Action outDeq();
        outQ.deq;
    endmethod

    method Action loadCuckooEntry(Bit#(1) tableIdx, Bit#(3) lenIdx, Bit#(9) hashIdx,
                                   Bit#(64) pattern, Bit#(16) ruleId) if (ckInitDone);
        CuckooEntry e = CuckooEntry { valid: True, pattern: pattern, ruleId: ruleId };
        Bit#(12) addr = {lenIdx, hashIdx};
        if (tableIdx == 0) ckTable1.upd(addr, e);
        else               ckTable2.upd(addr, e);
    endmethod

endmodule

endpackage: RuleReduction
