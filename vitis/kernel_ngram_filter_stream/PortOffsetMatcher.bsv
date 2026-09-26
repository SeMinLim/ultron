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
    Bool     isTcp;
    Bool     isUdp;
    Bool     isIcmp;
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

// Rule-indexed constraint entry (64-bit), one slot per ruleId.  Mirrors
// c_ref/mky_backup/port_offset_matcher.c: the matched rule's OWN port/proto/
// offset are checked, not a port-indexed window (which collides when many
// rules share a port — the rule16k bug).
//   [0]      valid
//   [8:1]    proto       (rule's IP protocol)
//   [9]      isRequest   (1 => compare dstPort, 0 => srcPort)
//   [25:10]  port
//   [27:26]  offsetMode  (0=any 1=small 2=big 3=exact)
//   [47:28]  offsetVal   (20-bit)
//   [55:48]  icmpType
//   [63:56]  icmpCode
typedef Bit#(64) PomEntry;

function Bool     ceValid(PomEntry e)    = (e[0:0] != 0);
function Bit#(8)  ceProto(PomEntry e)    = e[8:1];
function Bool     ceIsReq(PomEntry e)    = (e[9:9] != 0);
function Bit#(16) cePort(PomEntry e)     = e[25:10];
function Bit#(2)  ceOffMode(PomEntry e)  = e[27:26];
function Bit#(20) ceOffVal(PomEntry e)   = e[47:28];
function Bit#(8)  ceIcmpType(PomEntry e) = e[55:48];
function Bit#(8)  ceIcmpCode(PomEntry e) = e[63:56];

// c_ref group_match(): proto must match, then port (tcp/udp) or type+code (icmp).
function Bool groupMatch(PomEntry c, PomPktMeta m);
    Bit#(8) p   = ceProto(c);
    Bool    grp = (p == 6 || p == 17)
                    ? ((ceIsReq(c) ? m.dstPort : m.srcPort) == cePort(c))
                : (p == 1 || p == 58)
                    ? ((m.icmpType == ceIcmpType(c)) && (m.icmpCode == ceIcmpCode(c)))
                    : True;
    return (m.ipProto == p) && grp;
endfunction

// c_ref offset switch: 1=small (start<=min(payLen,val)), 2=big (start>=val),
// 3=exact (start==val), default=any.
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
    method Bool inputReady;
    method Bool outputReady;
    method Bool idle;
    method Bool processing;
    method Action writeConstraint(Bit#(16) addr, Bit#(64) data);
endinterface

(* synthesize *)
module mkPortOffsetMatcher(PortOffsetMatcherIfc);

    // One slot per ruleId (16-bit).  64 bits/rule × 65536 = 4 Mbit, smaller
    // than the old four port windows (4 × 2 Mbit) it replaces.
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize   = 65536;
    cfg.outFIFODepth = 2;
    BRAM2Port#(Bit#(16), Bit#(64)) ruleTbl <- mkBRAM2Server(cfg);

    FIFOF#(PomPktMeta) pendingQ <- mkSizedFIFOF(16);
    FIFOF#(PomPktMeta) stageBuf <- mkSizedFIFOF(2);
    FIFOF#(PomResult)  outQ     <- mkSizedFIFOF(16);

    rule issueReqs(pendingQ.notEmpty && stageBuf.notFull);
        let m = pendingQ.first; pendingQ.deq;
        ruleTbl.portA.request.put(BRAMRequest {
            write: False, responseOnWrite: False, address: m.ruleId, datain: ? });
        stageBuf.enq(m);
    endrule

    rule collectResps(stageBuf.notEmpty && outQ.notFull);
        let m = stageBuf.first; stageBuf.deq;
        let e <- ruleTbl.portA.response.get();
        Bool hit = ceValid(e) && groupMatch(e, m) && offsetMatch(e, m);
        outQ.enq(PomResult {
            hit:    hit,
            ruleId: hit ? m.ruleId : 0,
            group:  POM_None,
            isBig:  (ceOffMode(e) == 2),
            offset: zeroExtend(ceOffVal(e))
        });
    endrule

    method Action putMeta(PomPktMeta meta) if (pendingQ.notFull);
        pendingQ.enq(meta);
    endmethod

    method ActionValue#(PomResult) getResult if (outQ.notEmpty);
        let r = outQ.first; outQ.deq; return r;
    endmethod

    method Bool inputReady  = pendingQ.notFull;
    method Bool outputReady = outQ.notEmpty;
    method Bool idle        = !pendingQ.notEmpty && !stageBuf.notEmpty && !outQ.notEmpty;
    method Bool processing  = pendingQ.notEmpty || stageBuf.notEmpty;

    method Action writeConstraint(Bit#(16) addr, Bit#(64) data);
        ruleTbl.portB.request.put(BRAMRequest {
            write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod

endmodule

endpackage
