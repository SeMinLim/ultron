import BRAM::*;
import Vector::*;

typedef struct {
    Bit#(8) matchIndex;
    Bit#(8) matchLength;
} FpsmMatchKey deriving (Bits, Eq);

typedef Bit#(16) RuleId;

interface RuleTableIfc;
    method Action loadRule(FpsmMatchKey key, RuleId ruleId);
    method ActionValue#(Maybe#(RuleId)) lookup(FpsmMatchKey key);
endinterface

module mkRuleTable(RuleTableIfc);
    BRAM_Configure bramCfg = defaultValue;
    bramCfg.latency = 1;
    BRAM1Port#(Bit#(8), Maybe#(RuleId)) ruleTable <- mkBRAM1Server(bramCfg);

    function Bit#(8) hashKey(FpsmMatchKey key);
        return key.matchIndex ^ key.matchLength;
    endfunction

    method Action loadRule(FpsmMatchKey key, RuleId ruleId);
        Bit#(8) addr = hashKey(key);
        ruleTable.portA.request.put(BRAMRequest{
            write: True,
            responseOnWrite: False,
            address: addr,
            datain: tagged Valid ruleId
        });
    endmethod

    method ActionValue#(Maybe#(RuleId)) lookup(FpsmMatchKey key);
        Bit#(8) addr = hashKey(key);
        ruleTable.portA.request.put(BRAMRequest{
            write: False,
            responseOnWrite: False,
            address: addr,
            datain: tagged Invalid
        });
        let result <- ruleTable.portA.response.get();
        return result;
    endmethod
endmodule
