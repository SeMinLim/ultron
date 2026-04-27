package CycleCounter;

interface CycleCounterIfc;
    method Bit#(32) value;
    method Action   markStart;
    method Action   markDone;
    method Bit#(32) getStart;
    method Bit#(32) getDone;
    method Bit#(32) elapsed;
endinterface

(* synthesize *)
module mkCycleCounter(CycleCounterIfc);
    Reg#(Bit#(32)) counter    <- mkReg(0);
    Reg#(Bit#(32)) cycleStart <- mkReg(0);
    Reg#(Bit#(32)) cycleDone  <- mkReg(0);

    rule tick;
        counter <= counter + 1;
    endrule

    method Bit#(32) value    = counter;
    method Bit#(32) getStart = cycleStart;
    method Bit#(32) getDone  = cycleDone;
    method Bit#(32) elapsed  = cycleDone - cycleStart;

    method Action markStart;
        cycleStart <= counter;
    endmethod

    method Action markDone;
        cycleDone <= counter;
    endmethod
endmodule

interface E2ESpanIfc;
    method Action mark(Bit#(32) nowCycle);
    method Bit#(32) elapsed;
    method Action reset_;
endinterface

(* synthesize *)
module mkE2ESpan(E2ESpanIfc);
    Reg#(Bool)     seen     <- mkReg(False);
    Reg#(Bit#(32)) firstCyc <- mkReg(0);
    Reg#(Bit#(32)) lastCyc  <- mkReg(0);

    method Action mark(Bit#(32) nowCycle);
        if (!seen) begin
            seen     <= True;
            firstCyc <= nowCycle;
        end
        lastCyc <= nowCycle;
    endmethod

    method Bit#(32) elapsed = seen ? (lastCyc - firstCyc) : 0;

    method Action reset_;
        seen     <= False;
        firstCyc <= 0;
        lastCyc  <= 0;
    endmethod
endmodule

endpackage
