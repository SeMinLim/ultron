interface CycleCounterIfc;
	method Action start;
	method Action stop;
	method Bit#(32) current;
	method Bit#(32) elapsed;
endinterface

module mkCycleCounter(CycleCounterIfc);
	Reg#(Bit#(32)) counter   <- mkReg(0);
	Reg#(Bit#(32)) startCycle <- mkReg(0);
	Reg#(Bit#(32)) stopCycle  <- mkReg(0);

	rule incCycle;
		counter <= counter + 1;
	endrule

	method Action start;
		startCycle <= counter;
	endmethod

	method Action stop;
		stopCycle <= counter;
	endmethod

	method Bit#(32) current;
		return counter;
	endmethod

	method Bit#(32) elapsed;
		return stopCycle - startCycle;
	endmethod
endmodule
