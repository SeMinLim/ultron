import FIFOF::*;

typedef struct {
    Bit#(32) anchor;
    Bit#(32) base;
    Bit#(32) nCands;
} HashSeed deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) anchor;
    Bit#(32) base;
    Bit#(32) candIdx;
} VerifyRequest deriving (Bits, Eq, FShow);

interface HashTableIfc;
    method Action putSeed(HashSeed s);
    method ActionValue#(VerifyRequest) getRequest;

    method Bool seedReady;
    method Bool reqValid;
    method Bool busy;
endinterface

module mkHashTable(HashTableIfc);
    FIFOF#(HashSeed) inQ <- mkSizedFIFOF(1024);

    Reg#(Bool) active <- mkReg(False);
    Reg#(Bit#(32)) curAnchor <- mkReg(0);
    Reg#(Bit#(32)) curBase <- mkReg(0);
    Reg#(Bit#(32)) curN <- mkReg(0);
    Reg#(Bit#(32)) curIdx <- mkReg(0);

    rule loadSeed(!active && inQ.notEmpty);
        let s = inQ.first;
        inQ.deq;
        if (s.nCands != 0) begin
            active <= True;
            curAnchor <= s.anchor;
            curBase <= s.base;
            curN <= s.nCands;
            curIdx <= 0;
        end
    endrule

    method Action putSeed(HashSeed s) if (inQ.notFull);
        inQ.enq(s);
    endmethod

    method ActionValue#(VerifyRequest) getRequest if (active);
        let r = VerifyRequest {
            anchor: curAnchor,
            base: curBase,
            candIdx: curIdx
        };

        if (curIdx + 1 >= curN) begin
            active <= False;
        end else begin
            curIdx <= curIdx + 1;
        end

        return r;
    endmethod

    method Bool seedReady = inQ.notFull;
    method Bool reqValid = active;
    method Bool busy = inQ.notEmpty || active;
endmodule
