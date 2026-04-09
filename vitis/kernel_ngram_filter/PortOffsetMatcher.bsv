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
} PlmGroup deriving (Bits, Eq, FShow);

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
} PlmPktMeta deriving (Bits, Eq, FShow);

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    PlmGroup group;
    Bool     isBig;
    Bit#(32) offset;
} PlmResult deriving (Bits, Eq, FShow);

// PlmEntry (32-bit): [0]=valid [1]=isBig [15:2]=offset[13:0] [31:16]=matchKey
typedef Bit#(32) PlmEntry;

function Bool     plmValid(PlmEntry e)    = (e[0:0] != 0);
function Bool     plmIsBig(PlmEntry e)    = (e[1:1] != 0);
function Bit#(32) plmOffset(PlmEntry e)   = zeroExtend(e[15:2]);
function Bit#(16) plmPortKey(PlmEntry e)  = e[31:16];
function Bit#(8)  plmProtoKey(PlmEntry e) = e[23:16];
function Bit#(8)  plmIcmpCode(PlmEntry e) = e[23:16];

interface PortOffsetMatcherIfc;
    method Action putMeta(PlmPktMeta meta);
    method ActionValue#(PlmResult) getResult;
    method Bool inputReady;
    method Bool outputReady;
    // DbLoader init: port bitmap BRAMs (128 × 512-bit), tbl: 0=tcpDst 1=tcpSrc 2=udpDst 3=udpSrc
    method Action writeBitmap(Bit#(2) tbl, Bit#(7) addr, Bit#(512) data);
    // DbLoader init: port window BRAMs (1024 × 32-bit), tbl: 0=tcpDst 1=tcpSrc 2=udpDst 3=udpSrc
    method Action writeWindow(Bit#(2) tbl, Bit#(10) addr, Bit#(32) data);
    method Action writeIpProto(Bit#(8) addr, Bit#(32) data);
    method Action writeIcmp(Bit#(8) addr, Bit#(32) data);
endinterface

(* synthesize *)
module mkPortOffsetMatcher(PortOffsetMatcherIfc);

    BRAM_Configure bmCfg = defaultValue;
    bmCfg.memorySize   = 128;
    bmCfg.outFIFODepth = 2;

    BRAM2Port#(Bit#(7), Bit#(512)) tcpDstBm <- mkBRAM2Server(bmCfg);
    BRAM2Port#(Bit#(7), Bit#(512)) tcpSrcBm <- mkBRAM2Server(bmCfg);
    BRAM2Port#(Bit#(7), Bit#(512)) udpDstBm <- mkBRAM2Server(bmCfg);
    BRAM2Port#(Bit#(7), Bit#(512)) udpSrcBm <- mkBRAM2Server(bmCfg);

    BRAM_Configure winCfg = defaultValue;
    winCfg.memorySize   = 1024;
    winCfg.outFIFODepth = 2;

    BRAM2Port#(Bit#(10), Bit#(32)) tcpDstWin <- mkBRAM2Server(winCfg);
    BRAM2Port#(Bit#(10), Bit#(32)) tcpSrcWin <- mkBRAM2Server(winCfg);
    BRAM2Port#(Bit#(10), Bit#(32)) udpDstWin <- mkBRAM2Server(winCfg);
    BRAM2Port#(Bit#(10), Bit#(32)) udpSrcWin <- mkBRAM2Server(winCfg);

    BRAM_Configure ipCfg = defaultValue;
    ipCfg.memorySize   = 256;
    ipCfg.outFIFODepth = 2;
    BRAM2Port#(Bit#(8), Bit#(32)) ipProtoWin <- mkBRAM2Server(ipCfg);

    BRAM_Configure icmpCfg = defaultValue;
    icmpCfg.memorySize   = 256;
    icmpCfg.outFIFODepth = 2;
    BRAM2Port#(Bit#(8), Bit#(32)) icmpWin <- mkBRAM2Server(icmpCfg);

    FIFOF#(PlmPktMeta) pendingQ <- mkSizedFIFOF(16);
    FIFOF#(PlmPktMeta) stageBuf <- mkSizedFIFOF(2);
    FIFOF#(PlmResult)  outQ     <- mkSizedFIFOF(16);

    function Bool bmBitHit(Bit#(512) line, Bit#(9) pos);
        Bit#(512) shifted = line >> pos;
        return (shifted[0:0] != 0);
    endfunction

    function Bool inWindow(Bool isBig, Bit#(32) ruleOffset,
                           Bit#(32) matchPos, Bit#(32) payloadLen);
        if (isBig) begin
            return (matchPos >= ruleOffset);
        end else begin
            Bit#(32) ceiling = (payloadLen < ruleOffset) ? payloadLen : ruleOffset;
            return (matchPos <= ceiling);
        end
    endfunction

    rule issueReqs(pendingQ.notEmpty && stageBuf.notFull);
        let m = pendingQ.first; pendingQ.deq;

        tcpDstBm.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.dstPort[15:9], datain: ? });
        tcpSrcBm.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.srcPort[15:9], datain: ? });
        udpDstBm.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.dstPort[15:9], datain: ? });
        udpSrcBm.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.srcPort[15:9], datain: ? });

        tcpDstWin.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.dstPort[9:0], datain: ? });
        tcpSrcWin.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.srcPort[9:0], datain: ? });
        udpDstWin.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.dstPort[9:0], datain: ? });
        udpSrcWin.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.srcPort[9:0], datain: ? });

        ipProtoWin.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: m.ipProto,   datain: ? });
        icmpWin.portA.request.put(   BRAMRequest { write: False, responseOnWrite: False, address: m.icmpType,  datain: ? });

        stageBuf.enq(m);
    endrule

    rule collectResps(stageBuf.notEmpty && outQ.notFull);
        let m = stageBuf.first; stageBuf.deq;

        let tcpDstLine <- tcpDstBm.portA.response.get();
        let tcpSrcLine <- tcpSrcBm.portA.response.get();
        let udpDstLine <- udpDstBm.portA.response.get();
        let udpSrcLine <- udpSrcBm.portA.response.get();

        let tcpDstE  <- tcpDstWin.portA.response.get();
        let tcpSrcE  <- tcpSrcWin.portA.response.get();
        let udpDstE  <- udpDstWin.portA.response.get();
        let udpSrcE  <- udpSrcWin.portA.response.get();
        let ipProtoE <- ipProtoWin.portA.response.get();
        let icmpE    <- icmpWin.portA.response.get();

        Bool tcpDstHit = m.isTcp && bmBitHit(tcpDstLine, m.dstPort[8:0]) && plmValid(tcpDstE) && plmPortKey(tcpDstE) == m.dstPort;
        Bool tcpSrcHit = m.isTcp && bmBitHit(tcpSrcLine, m.srcPort[8:0]) && plmValid(tcpSrcE) && plmPortKey(tcpSrcE) == m.srcPort;
        Bool udpDstHit = m.isUdp && bmBitHit(udpDstLine, m.dstPort[8:0]) && plmValid(udpDstE) && plmPortKey(udpDstE) == m.dstPort;
        Bool udpSrcHit = m.isUdp && bmBitHit(udpSrcLine, m.srcPort[8:0]) && plmValid(udpSrcE) && plmPortKey(udpSrcE) == m.srcPort;
        Bool ipHit     = plmValid(ipProtoE) && plmProtoKey(ipProtoE) == m.ipProto;
        Bool icmpHit   = m.isIcmp && plmValid(icmpE) && (plmIcmpCode(icmpE) == 8'hFF || plmIcmpCode(icmpE) == m.icmpCode);

        PlmGroup grp =
            tcpDstHit ? POM_TcpDstPort   :
            tcpSrcHit ? POM_TcpSrcPort   :
            udpDstHit ? POM_UdpDstPort   :
            udpSrcHit ? POM_UdpSrcPort   :
            ipHit     ? POM_IpProto      :
            icmpHit   ? POM_IcmpTypeCode :
                        POM_None;

        PlmEntry winE =
            tcpDstHit ? tcpDstE  :
            tcpSrcHit ? tcpSrcE  :
            udpDstHit ? udpDstE  :
            udpSrcHit ? udpSrcE  :
            ipHit     ? ipProtoE :
            icmpHit   ? icmpE    : 0;

        Bool groupHit = (grp != POM_None);
        Bool winOk    = groupHit && inWindow(plmIsBig(winE), plmOffset(winE), m.matchPos, m.payloadLen);

        outQ.enq(PlmResult {
            hit:    winOk,
            ruleId: winOk ? m.ruleId : 0,
            group:  winOk ? grp : POM_None,
            isBig:  plmIsBig(winE),
            offset: plmOffset(winE)
        });
    endrule

    method Action putMeta(PlmPktMeta meta) if (pendingQ.notFull);
        pendingQ.enq(meta);
    endmethod

    method ActionValue#(PlmResult) getResult if (outQ.notEmpty);
        let r = outQ.first; outQ.deq; return r;
    endmethod

    method Bool inputReady  = pendingQ.notFull;
    method Bool outputReady = outQ.notEmpty;

    method Action writeBitmap(Bit#(2) tbl, Bit#(7) addr, Bit#(512) data);
        let req = BRAMRequest { write: True, responseOnWrite: False, address: addr, datain: data };
        case (tbl)
            2'd0: tcpDstBm.portB.request.put(req);
            2'd1: tcpSrcBm.portB.request.put(req);
            2'd2: udpDstBm.portB.request.put(req);
            2'd3: udpSrcBm.portB.request.put(req);
        endcase
    endmethod

    method Action writeWindow(Bit#(2) tbl, Bit#(10) addr, Bit#(32) data);
        let req = BRAMRequest { write: True, responseOnWrite: False, address: addr, datain: data };
        case (tbl)
            2'd0: tcpDstWin.portB.request.put(req);
            2'd1: tcpSrcWin.portB.request.put(req);
            2'd2: udpDstWin.portB.request.put(req);
            2'd3: udpSrcWin.portB.request.put(req);
        endcase
    endmethod

    method Action writeIpProto(Bit#(8) addr, Bit#(32) data);
        ipProtoWin.portB.request.put(BRAMRequest { write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod

    method Action writeIcmp(Bit#(8) addr, Bit#(32) data);
        icmpWin.portB.request.put(BRAMRequest { write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod

endmodule

endpackage
