package ResultStreamWriter;

import RegFile::*;

import AxiStream::*;

typedef 128 ResultOrderDepth;
typedef TLog#(ResultOrderDepth) SlotW;   // 7

typedef struct {
    Bit#(32) pktIdx;
    Bool     matched;
    Bit#(16) ruleId;
    Bit#(15) latency;
} OrderedResult deriving (Bits);

interface ResultStreamWriterIfc;
    method Action emitHeader(Bit#(32) val);                    // db_load header beat
    method Action emitFooter(Bit#(32) val);                    // process-cycles footer beat
    method Bool   canAccept(Bit#(32) pktIdx);                  // defensive collision check
    method Bool   canAdmit(Bit#(32) pktIdx);                   // admission gate (window)
    method Action addResult(Bit#(32) pktIdx, Bool matched,
                            Bit#(16) ruleId, Bit#(15) latency);
    method Bit#(32) dbgNextOut;
endinterface

module mkResultStreamWriter#(AxiStreamMasterIfc#(32) axisOut)
                            (ResultStreamWriterIfc);

    Reg#(Bit#(32)) nextOutPktIdx <- mkReg(0);
    RegFile#(Bit#(SlotW), OrderedResult) buf_ <- mkRegFileFull;
    Reg#(Bit#(ResultOrderDepth)) validVec <- mkReg(0);
    RWire#(Bit#(SlotW)) setSlot   <- mkRWire;
    RWire#(Bit#(SlotW)) clearSlot <- mkRWire;

    Reg#(Bool)     headerArmed <- mkReg(False);
    Reg#(Bool)     headerSent  <- mkReg(False);
    Reg#(Bit#(32)) headerVal   <- mkRegU;   // written with headerArmed
    Reg#(Bool)     footerArmed <- mkReg(False);
    Reg#(Bool)     footerSent  <- mkReg(False);
    Reg#(Bit#(32)) footerVal   <- mkRegU;   // written with footerArmed

    function Bit#(ResultOrderDepth) bit1(Bit#(SlotW) s) = (1 << s);

    rule sendHeader(headerArmed && !headerSent);
        axisOut.put(headerVal, 4'hF, True);
        headerSent  <= True;
    endrule

    rule sendFooter(footerArmed && !footerSent && headerSent && validVec == 0);
        axisOut.put(footerVal, 4'hF, True);
        footerSent  <= True;
    endrule

    (* fire_when_enabled, no_implicit_conditions *)
    rule updateValid;
        Bit#(ResultOrderDepth) v = validVec;
        if (clearSlot.wget matches tagged Valid .c) v = v & ~bit1(c);
        if (setSlot.wget   matches tagged Valid .s) v = v |  bit1(s);
        validVec <= v;
    endrule

    // Exclusive in practice (the footer needs an empty buffer); states bsc's order.
    (* descending_urgency = "sendFooter, drainOrdered" *)
    rule drainOrdered(headerSent);
        Bit#(SlotW) hslot = truncate(nextOutPktIdx);
        let e = buf_.sub(hslot);
        if (validVec[hslot] == 1 && e.pktIdx == nextOutPktIdx) begin
            Bit#(32) rword = {e.latency, e.ruleId, pack(e.matched)};
            axisOut.put(rword, 4'hF, True);
            clearSlot.wset(hslot);
            nextOutPktIdx <= nextOutPktIdx + 1;
        end
    endrule

    method Action emitHeader(Bit#(32) val);
        headerVal   <= val;
        headerArmed <= True;
    endmethod

    method Action emitFooter(Bit#(32) val);
        footerVal   <= val;
        footerArmed <= True;
    endmethod

    method Bool canAccept(Bit#(32) pktIdx);
        Bit#(SlotW) slot = truncate(pktIdx);
        return (validVec[slot] == 0);
    endmethod

    method Bool canAdmit(Bit#(32) pktIdx);
        return (pktIdx - nextOutPktIdx) < fromInteger(valueOf(ResultOrderDepth));
    endmethod

    method Action addResult(Bit#(32) pktIdx, Bool matched,
                            Bit#(16) ruleId, Bit#(15) latency);
        Bit#(SlotW) slot = truncate(pktIdx);
        buf_.upd(slot, OrderedResult { pktIdx: pktIdx, matched: matched,
                                       ruleId: ruleId, latency: latency });
        setSlot.wset(slot);
    endmethod
    method Bit#(32) dbgNextOut = nextOutPktIdx;
endmodule

endpackage
