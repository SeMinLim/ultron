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
    method Action configure;
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
    // Data store: one OrderedResult per slot (RegFile = LUTRAM, not FFs).
    RegFile#(Bit#(SlotW), OrderedResult) buf_ <- mkRegFileFull;
    // Per-slot occupancy as one packed register (set on write, clear on emit).
    Reg#(Bit#(ResultOrderDepth)) validVec <- mkReg(0);
    RWire#(Bit#(SlotW)) setSlot   <- mkRWire;
    RWire#(Bit#(SlotW)) clearSlot <- mkRWire;

    // One-time header beat = db-load cycles (emitted before any packet result);
    // one-time footer beat = total packet-processing cycles (emitted after the
    // last packet result, once the kernel goes idle). Together they give the host
    // a proper db_load vs process split with NO per-packet overlap confusion.
    Reg#(Bool)     headerArmed <- mkReg(False);
    Reg#(Bool)     headerSent  <- mkReg(False);
    Reg#(Bit#(32)) headerVal   <- mkReg(0);
    Reg#(Bool)     footerArmed <- mkReg(False);
    Reg#(Bool)     footerSent  <- mkReg(False);
    Reg#(Bit#(32)) footerVal   <- mkReg(0);

    function Bit#(ResultOrderDepth) bit1(Bit#(SlotW) s) = (1 << s);

    rule sendHeader(headerArmed && !headerSent);
        axisOut.put(headerVal, 4'hF, True);
        headerSent  <= True;
        headerArmed <= False;
    endrule

    // Footer goes out only after every packet result has drained (validVec==0).
    rule sendFooter(footerArmed && !footerSent && headerSent && validVec == 0);
        axisOut.put(footerVal, 4'hF, True);
        footerSent  <= True;
        footerArmed <= False;
    endrule

    (* fire_when_enabled, no_implicit_conditions *)
    rule updateValid;
        Bit#(ResultOrderDepth) v = validVec;
        if (clearSlot.wget matches tagged Valid .c) v = v & ~bit1(c);
        if (setSlot.wget   matches tagged Valid .s) v = v |  bit1(s);
        validVec <= v;
    endrule

    // Emit the in-order head whenever present (after the header beat). One
    // 32-bit beat, tlast=1.
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

    method Action configure;
        nextOutPktIdx <= 0;
        validVec      <= 0;
        headerSent    <= False;
        headerArmed   <= False;
        footerSent    <= False;
        footerArmed   <= False;
    endmethod

    // Arm the one-time db_load header beat (emitted before any packet result).
    method Action emitHeader(Bit#(32) val);
        headerVal   <= val;
        headerArmed <= True;
    endmethod

    // Arm the one-time process-cycles footer beat (emitted after the last result).
    method Action emitFooter(Bit#(32) val);
        footerVal   <= val;
        footerArmed <= True;
    endmethod

    // Defensive: slot not currently occupied (the gate makes aliasing impossible,
    // but keep this so a stray collision can never overwrite a live result).
    method Bool canAccept(Bit#(32) pktIdx);
        Bit#(SlotW) slot = truncate(pktIdx);
        return (validVec[slot] == 0);
    endmethod

    // Admission gate: pkt is within the reorder window of the output head. Pure
    // arithmetic on nextOutPktIdx (no array read) -> no scheduling cycle.
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
