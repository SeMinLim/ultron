

package HeaderMatcher;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import RegFile::*;
import PacketParserTypes::*;
import TrafficManager::*;
import RuleReduction::*;

typedef struct {
    Bit#(8)  proto;
    Bit#(16) srcPortMin;
    Bit#(16) srcPortMax;
    Bit#(16) dstPortMin;
    Bit#(16) dstPortMax;
} PortGroupSpec deriving (Bits, Eq);

interface HeaderMatcherIfc;
    method Action put(Vector#(MaxCandidates, Maybe#(Bit#(16))) ruleIds,
                      PacketMeta meta);
    method Bool   outValid();
    method Vector#(8, HeaderMatchResult) outResults();
    method PacketMeta outMeta();
    method Action outDeq();

    method Action stageRulePg(Bit#(16) ruleId, Bit#(8) pgId, Bit#(8) proto);
    method Action stageSrcPorts(Bit#(16) srcMin, Bit#(16) srcMax);
    method Action commitDstPorts(Bit#(16) dstMin, Bit#(16) dstMax);
endinterface

module mkHeaderMatcher(HeaderMatcherIfc);

    Vector#(8, RegFile#(Bit#(9), Bit#(8))) ruleToPg
        <- replicateM(mkRegFileFull());

    Vector#(8, RegFile#(Bit#(8), PortGroupSpec)) pgSpec
        <- replicateM(mkRegFileFull());

    Reg#(Bit#(16)) stRuleId <- mkReg(0);
    Reg#(Bit#(8))  stPgId   <- mkReg(0);
    Reg#(Bit#(8))  stProto  <- mkReg(0);
    Reg#(Bit#(16)) stSrcMin <- mkReg(0);
    Reg#(Bit#(16)) stSrcMax <- mkReg(16'hFFFF);

    FIFO#(Tuple2#(Vector#(MaxCandidates, Maybe#(Bit#(16))), PacketMeta)) inQ
        <- mkFIFO;
    FIFOF#(Tuple2#(Vector#(8, HeaderMatchResult), PacketMeta)) outQ
        <- mkFIFOF;

    rule doHdrCheck;
        match {.cands, .meta} = inQ.first;
        inQ.deq;

        Vector#(8, HeaderMatchResult) results =
            replicate(HeaderMatchResult { valid: False, laneIdx: 0,
                                          matchLen: 0, ruleId: 0 });

        for (Integer i = 0; i < 8; i = i + 1) begin
            if (cands[i] matches tagged Valid .rid) begin

                Bit#(8) pgId = ruleToPg[i].sub(truncate(rid));

                PortGroupSpec pg = pgSpec[i].sub(pgId);

                Bool protoOk = (pg.proto == 0) || (pg.proto == meta.protocol);
                Bool srcOk   = (meta.srcPort >= pg.srcPortMin) &&
                               (meta.srcPort <= pg.srcPortMax);
                Bool dstOk   = (meta.dstPort >= pg.dstPortMin) &&
                               (meta.dstPort <= pg.dstPortMax);

                results[i] = HeaderMatchResult {
                    valid:    protoOk && srcOk && dstOk,
                    laneIdx:  0,
                    matchLen: 4,
                    ruleId:   rid
                };
            end
        end
        outQ.enq(tuple2(results, meta));
    endrule

    method Action put(Vector#(MaxCandidates, Maybe#(Bit#(16))) ruleIds,
                      PacketMeta meta);
        inQ.enq(tuple2(ruleIds, meta));
    endmethod

    method Bool   outValid()   = outQ.notEmpty;

    method Vector#(8, HeaderMatchResult) outResults();
        return tpl_1(outQ.first);
    endmethod

    method PacketMeta outMeta();
        return tpl_2(outQ.first);
    endmethod

    method Action outDeq();
        outQ.deq;
    endmethod

    method Action stageRulePg(Bit#(16) ruleId, Bit#(8) pgId, Bit#(8) proto);
        stRuleId <= ruleId;
        stPgId   <= pgId;
        stProto  <= proto;
    endmethod

    method Action stageSrcPorts(Bit#(16) srcMin, Bit#(16) srcMax);
        stSrcMin <= srcMin;
        stSrcMax <= srcMax;
    endmethod

    method Action commitDstPorts(Bit#(16) dstMin, Bit#(16) dstMax);
        PortGroupSpec spec = PortGroupSpec {
            proto:      stProto,
            srcPortMin: stSrcMin,
            srcPortMax: stSrcMax,
            dstPortMin: dstMin,
            dstPortMax: dstMax
        };
        for (Integer i = 0; i < 8; i = i + 1) begin
            ruleToPg[i].upd(truncate(stRuleId), stPgId);
            pgSpec[i].upd(stPgId, spec);
        end
    endmethod

endmodule

endpackage: HeaderMatcher
