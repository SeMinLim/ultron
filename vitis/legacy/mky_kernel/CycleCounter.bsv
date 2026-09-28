interface CycleCounterIfc;
    method Bit#(32) value;
    method Action markStart;
    method Action markDone;
    method Bit#(32) getStart;
    method Bit#(32) getDone;
endinterface

module mkCycleCounter(CycleCounterIfc);
    Reg#(Bit#(32)) cycleCounter <- mkReg(0);
    Reg#(Bit#(32)) cycleStart <- mkReg(0);
    Reg#(Bit#(32)) cycleDone <- mkReg(0);

    rule incCycle;
        cycleCounter <= cycleCounter + 1;
    endrule

    method Bit#(32) value = cycleCounter;
    method Bit#(32) getStart = cycleStart;
    method Bit#(32) getDone = cycleDone;

    method Action markStart;
        cycleStart <= cycleCounter;
    endmethod

    method Action markDone;
        cycleDone <= cycleCounter;
    endmethod
endmodule
