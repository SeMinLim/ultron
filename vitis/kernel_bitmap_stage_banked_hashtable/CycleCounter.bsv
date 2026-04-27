package CycleCounter;

interface CycleCounterIfc;
    method Bit#(32) value;
    method Action   markStart;
    method Action   markDone;
    method Bit#(32) getStart;
    method Bit#(32) getDone;
    method Bit#(32) elapsed;   // getDone - getStart
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

endpackage
