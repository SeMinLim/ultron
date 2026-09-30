package PortOffsetMatcher;

import FIFOF::*;
import BRAM::*;

typedef enum {
    POM_TcpDstPort,
    POM_TcpSrcPort,
    POM_UdpDstPort,
    POM_UdpSrcPort,
    POM_IpProto,
    POM_IcmpTypeCode,
    POM_None
} PomGroup deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(16) ruleId;
    Bit#(8)  ipProto;
    Bit#(16) srcPort;
    Bit#(16) dstPort;
    Bit#(8)  icmpType;
    Bit#(8)  icmpCode;
    Bit#(32) matchPos;
    Bit#(32) payloadLen;
} PomPktMeta deriving (Bits, Eq, FShow);

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    PomGroup group;
    Bool     isBig;
    Bit#(32) offset;
} PomResult deriving (Bits, Eq, FShow);

typedef Bit#(64) PomEntry;

function Bool     ceValid(PomEntry e)    = (e[0:0] != 0);
function Bit#(8)  ceProto(PomEntry e)    = e[8:1];
function Bool     ceIsReq(PomEntry e)    = (e[9:9] != 0);
function Bit#(16) cePort(PomEntry e)     = e[25:10];
function Bit#(2)  ceOffMode(PomEntry e)  = e[27:26];
function Bit#(20) ceOffVal(PomEntry e)   = e[47:28];
function Bit#(8)  ceIcmpType(PomEntry e) = e[55:48];
function Bit#(8)  ceIcmpCode(PomEntry e) = e[63:56];

function Bool groupMatch(PomEntry c, PomPktMeta m);
    Bit#(8) p   = ceProto(c);
    Bool    grp = (p == 6 || p == 17)
                    ? ((ceIsReq(c) ? m.dstPort : m.srcPort) == cePort(c))
                : (p == 1 || p == 58)
                    ? ((m.icmpType == ceIcmpType(c)) && (m.icmpCode == ceIcmpCode(c)))
                    : True;
    return (m.ipProto == p) && grp;
endfunction

function Bool offsetMatch(PomEntry c, PomPktMeta m);
    Bit#(32) val     = zeroExtend(ceOffVal(c));
    Bit#(32) ceiling = (m.payloadLen < val) ? m.payloadLen : val;
    return case (ceOffMode(c))
        2'd1:    (m.matchPos <= ceiling);
        2'd2:    (m.matchPos >= val);
        2'd3:    (m.matchPos == val);
        default: True;
    endcase;
endfunction

interface PortOffsetMatcherIfc;
    method Action putMeta(PomPktMeta meta);
    method ActionValue#(PomResult) getResult;
    method Action writeConstraint(Bit#(16) addr, Bit#(64) data);
endinterface

(* synthesize *)
module mkPortOffsetMatcher(PortOffsetMatcherIfc);

    BRAM_Configure cfg = defaultValue;
    cfg.memorySize   = 8192;
    cfg.latency      = 2;
    cfg.outFIFODepth = 4;
    BRAM2Port#(Bit#(16), Bit#(64)) ruleTbl <- mkBRAM2Server(cfg);

    FIFOF#(PomPktMeta) pendingQ <- mkSizedFIFOF(16);
    FIFOF#(PomPktMeta) stageBuf <- mkSizedFIFOF(4);
    FIFOF#(Tuple2#(PomEntry, PomPktMeta)) evalQ <- mkFIFOF;
    FIFOF#(PomResult)  outQ     <- mkSizedFIFOF(16);

    rule issueReqs;
        let m = pendingQ.first; pendingQ.deq;
        ruleTbl.portA.request.put(BRAMRequest {
            write: False, responseOnWrite: False, address: m.ruleId, datain: ? });
        stageBuf.enq(m);
    endrule

    rule collectResps;
        let m = stageBuf.first; stageBuf.deq;
        let e <- ruleTbl.portA.response.get();
        evalQ.enq(tuple2(e, m));
    endrule

    rule evalResp;
        match { .e, .m } = evalQ.first; evalQ.deq;
        Bool hit = ceValid(e) && groupMatch(e, m) && offsetMatch(e, m);
        outQ.enq(PomResult {
            hit:    hit,
            ruleId: hit ? m.ruleId : 0,
            group:  POM_None,
            isBig:  (ceOffMode(e) == 2),
            offset: zeroExtend(ceOffVal(e))
        });
    endrule

    method Action putMeta(PomPktMeta meta);
        pendingQ.enq(meta);
    endmethod

    method ActionValue#(PomResult) getResult;
        let r = outQ.first; outQ.deq; return r;
    endmethod


    method Action writeConstraint(Bit#(16) addr, Bit#(64) data);
        ruleTbl.portB.request.put(BRAMRequest {
            write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod

endmodule

endpackage
