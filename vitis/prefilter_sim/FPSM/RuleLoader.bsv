package RuleLoader;

import Vector::*;
import BRAM::*;
import FIFOF::*;
import GetPut::*;

typedef struct {
    Bit#(16) ruleId;
    Bit#(8)  protocol;
    Bit#(16) port;
    Bit#(8)  direction;
    Bit#(256) pattern;
    Bit#(8)  patternLen;
    Bit#(256) shiftOrMask;
} Rule deriving (Bits, Eq);

typedef 512 MaxRules;

interface RuleLoaderIfc;
    method Action loadRule(Bit#(16) idx, Rule rule);
    method ActionValue#(Rule) getRule(Bit#(16) idx);
    method Bit#(256) calcShiftOrMask(Bit#(256) pattern, Bit#(8) len);
    method Bool isLoaded();
endinterface

module mkRuleLoader(RuleLoaderIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.latency = 1;
    BRAM2Port#(Bit#(9), Rule) ruleBram <- mkBRAM2Server(cfg);

    Reg#(Bool) loaded <- mkReg(False);
    Reg#(Bit#(16)) rulesLoaded <- mkReg(0);

    FIFOF#(Bit#(16)) getRuleReqQ <- mkFIFOF;
    FIFOF#(Rule) getRuleRespQ <- mkFIFOF;

    function Bit#(256) calculateShiftOrMask(Bit#(256) pattern, Bit#(8) len);
        Bit#(256) mask = 0;

        for (Integer i = 0; i < 32; i = i + 1) begin
            if (fromInteger(i) < len) begin
                Bit#(8) byte = pattern[i*8+7 : i*8];
                mask[i*8+7 : i*8] = byte;
            end
        end

        return mask;
    endfunction

    method Action loadRule(Bit#(16) idx, Rule rule);
        ruleBram.portA.request.put(BRAMRequest{
            write: True,
            responseOnWrite: False,
            address: truncate(idx),
            datain: rule
        });

        rulesLoaded <= rulesLoaded + 1;
        if (rulesLoaded + 1 >= 275) begin
            loaded <= True;
        end
    endmethod

    method ActionValue#(Rule) getRule(Bit#(16) idx);
        ruleBram.portB.request.put(BRAMRequest{
            write: False,
            responseOnWrite: False,
            address: truncate(idx),
            datain: ?
        });

        let rule <- ruleBram.portB.response.get();
        return rule;
    endmethod

    method Bit#(256) calcShiftOrMask(Bit#(256) pattern, Bit#(8) len);
        return calculateShiftOrMask(pattern, len);
    endmethod

    method Bool isLoaded();
        return loaded;
    endmethod
endmodule

function Bit#(256) parseHexPattern(String hexStr);
    return 0;
endfunction

function Bit#(8) hexToByte(Bit#(8) h1, Bit#(8) h0);
    function Bit#(4) hexDigit(Bit#(8) c);
        if (c >= 48 && c <= 57) return truncate(c - 48);
        else if (c >= 65 && c <= 70) return truncate(c - 55);
        else if (c >= 97 && c <= 102) return truncate(c - 87);
        else return 0;
    endfunction

    return {hexDigit(h1), hexDigit(h0)};
endfunction

endpackage: RuleLoader
