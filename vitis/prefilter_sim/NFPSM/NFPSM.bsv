

package NFPSM;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import RegFile::*;
import PacketParserTypes::*;
import RuleReduction::*;

function Bit#(8) nfpsmGetByte(Bit#(256) payload, Integer i);
    Integer half = (i / 16) * 128;
    Integer pos  = i % 16;
    Integer lo   = half + (15 - pos) * 8;
    return payload[lo + 7 : lo];
endfunction

function Bit#(9) nfpsmHashBytes(Bit#(256) payload, Integer k, Integer len);
    Bit#(9) h = 0;
    for (Integer i = 0; i < 8; i = i + 1)
        if (i < len && k + i < 32) begin
            Bit#(9) b = zeroExtend(nfpsmGetByte(payload, k + i));
            Integer r = (i * 3) % 9;
            h = h ^ ((b << fromInteger(r)) | (b >> fromInteger(9 - r)));
        end
    return h;
endfunction

interface SimpleNFPSMIfc;

    method Bit#(128) process(Bit#(256) payload);
    method Action loadBTableEntry(Bit#(8) charIdx, Bit#(8) mask);
    method Action loadHTBit(Bit#(3) lenIdx, Bit#(9) hashIdx);
endinterface

(* synthesize *)
module mkSimpleNFPSM(SimpleNFPSMIfc);

    Vector#(8, Reg#(Bit#(256))) bMask      <- replicateM(mkReg(0));
    Vector#(8, Reg#(Bit#(512))) hashTables <- replicateM(mkReg(0));

    method Bit#(128) process(Bit#(256) payload);
        Bit#(128) result = 0;

        for (Integer k = 0; k < 16; k = k + 1) begin
            Bit#(8) d = 0;
            for (Integer j = 0; j < 8; j = j + 1) begin
                Bit#(8) bv  = 0;
                Bit#(8) byt = nfpsmGetByte(payload, k + j);
                for (Integer p = 0; p < 8; p = p + 1)
                    bv = bv | (zeroExtend(bMask[p][byt]) << fromInteger(p));

                d = ((d << 1) | 1) & bv;

                if (d[j] == 1) begin
                    Bit#(9) h     = nfpsmHashBytes(payload, k, j + 1);
                    Bit#(1) htBit = hashTables[j][h];
                    if (htBit == 1)
                        result[k * 8 + j] = 1;
                end
            end
        end

        return result;
    endmethod

    method Action loadBTableEntry(Bit#(8) charIdx, Bit#(8) mask);
        Bit#(256) one256 = 1;
        Bit#(256) bit_pos = one256 << charIdx;
        for (Integer j = 0; j < 8; j = j + 1)
            if (mask[j] == 1)
                bMask[j] <= bMask[j] | bit_pos;
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
endmodule

function Vector#(2, Maybe#(Bit#(16)))
         compactTo2(Vector#(8, Maybe#(Bit#(16))) ids);
    Vector#(2, Maybe#(Bit#(16))) out = replicate(tagged Invalid);
    Bool slot0Set = False;
    Bool slot1Set = False;
    for (Integer i = 0; i < 8; i = i + 1) begin
        if (ids[i] matches tagged Valid .v) begin
            if (!slot0Set) begin
                out[0]   = tagged Valid v;
                slot0Set = True;
            end else if (!slot1Set) begin
                out[1]   = tagged Valid v;
                slot1Set = True;
            end
        end
    end
    return out;
endfunction

interface NFPSMIfc;

    method Action putSuspicious(Bit#(128) fp,
                                Vector#(MaxCandidates, Maybe#(Bit#(16))) ruleIds,
                                PacketMeta meta);

    method Bool       outValid();
    method Bool       needsCPU();
    method PacketMeta outMeta();
    method Action     outDeq();

    method Action loadRuleFP(Bit#(9) ruleId, Bit#(3) seg, Bit#(16) bits16);
    method Bit#(32) getCPUCount();
    method Bit#(32) getCleanCount();
endinterface

module mkNFPSM(NFPSMIfc);

    Vector#(8, RegFile#(Bit#(9), Bit#(16))) ruleFPSegs
        <- replicateM(mkRegFileFull());

    FIFOF#(Tuple3#(Bit#(128), Vector#(MaxCandidates, Maybe#(Bit#(16))), PacketMeta))
        inQ <- mkFIFOF;

    FIFOF#(Tuple2#(Bool, PacketMeta)) outQ <- mkFIFOF;

    Reg#(Bool)    initialized <- mkReg(False);
    Reg#(Bit#(9)) initIdx     <- mkReg(0);

    rule initRuleFP(!initialized);
        for (Integer s = 0; s < 8; s = s + 1)
            ruleFPSegs[s].upd(initIdx, 0);
        if (initIdx == 9'h1FF)
            initialized <= True;
        else
            initIdx <= initIdx + 1;
    endrule

    Reg#(Bool)     scanning    <- mkReg(False);
    Reg#(Bit#(1))  scanIdx     <- mkReg(0);
    Reg#(Bit#(128))  curPktFP  <- mkReg(0);
    Reg#(PacketMeta) curMeta   <- mkReg(?);
    Reg#(Vector#(2, Maybe#(Bit#(16)))) curIds2 <- mkReg(?);
    Reg#(Bool)     anySurvivor <- mkReg(False);

    Reg#(Bit#(32)) cpuCount      <- mkReg(0);
    Reg#(Bit#(32)) cleanCount    <- mkReg(0);

    rule startScan(initialized && !scanning && inQ.notEmpty);
        Bit#(128)  fp   = tpl_1(inQ.first);
        Vector#(MaxCandidates, Maybe#(Bit#(16))) ids = tpl_2(inQ.first);
        PacketMeta meta = tpl_3(inQ.first);
        inQ.deq;
        curPktFP    <= fp;
        curMeta     <= meta;
        curIds2     <= compactTo2(ids);
        scanning    <= True;
        scanIdx     <= 0;
        anySurvivor <= False;
    endrule

    rule doScan(scanning);
        Bool newAnySurvivor = anySurvivor;

        Maybe#(Bit#(16)) curCand = (scanIdx == 0) ? curIds2[0] : curIds2[1];

        if (curCand matches tagged Valid .rid) begin

            Bit#(128) ruleFP = 0;
            for (Integer s = 0; s < 8; s = s + 1) begin
                Bit#(16) seg = ruleFPSegs[s].sub(truncate(rid));
                ruleFP = ruleFP | (zeroExtend(seg) << fromInteger(s * 16));
            end

            if ((ruleFP & ~curPktFP) == 0) newAnySurvivor = True;
        end

        anySurvivor <= newAnySurvivor;
        scanIdx <= scanIdx + 1;

        if (scanIdx == 1) begin
            scanning <= False;
            outQ.enq(tuple2(newAnySurvivor, curMeta));
        end
    endrule

    method Action putSuspicious(Bit#(128) fp,
                                Vector#(MaxCandidates, Maybe#(Bit#(16))) ruleIds,
                                PacketMeta meta);
        inQ.enq(tuple3(fp, ruleIds, meta));
    endmethod

    method Bool       outValid()  = outQ.notEmpty;
    method Bool       needsCPU()  = tpl_1(outQ.first);
    method PacketMeta outMeta()   = tpl_2(outQ.first);

    method Action outDeq;
        Bool cpu = tpl_1(outQ.first);
        outQ.deq;
        if (cpu) cpuCount   <= cpuCount   + 1;
        else     cleanCount <= cleanCount + 1;
    endmethod

    method Action loadRuleFP(Bit#(9) ruleId, Bit#(3) seg, Bit#(16) bits16);
        case (seg)
            3'd0: ruleFPSegs[0].upd(ruleId, bits16);
            3'd1: ruleFPSegs[1].upd(ruleId, bits16);
            3'd2: ruleFPSegs[2].upd(ruleId, bits16);
            3'd3: ruleFPSegs[3].upd(ruleId, bits16);
            3'd4: ruleFPSegs[4].upd(ruleId, bits16);
            3'd5: ruleFPSegs[5].upd(ruleId, bits16);
            3'd6: ruleFPSegs[6].upd(ruleId, bits16);
            3'd7: ruleFPSegs[7].upd(ruleId, bits16);
        endcase
    endmethod

    method Bit#(32) getCPUCount()    = cpuCount;
    method Bit#(32) getCleanCount()  = cleanCount;

endmodule

endpackage: NFPSM
