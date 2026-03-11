package RuleLoader;

typedef struct {
  Bit#(64) payload64;
  Bit#(64) rule64;
  Bit#(8) patternLen;
  Bit#(32) ruleId;
  Bit#(8) ruleProto;
  Bit#(16) portGroupId;
  Bit#(2) portGroupType;
  Bit#(16) groupPortSingle;
  Bit#(16) groupRangeStart;
  Bit#(16) groupRangeEnd;
  Bit#(16) nfFingerprint;
  Bool nfEnable;
  Bit#(2) portDirection;
} RuleLoadFields deriving (Bits, Eq);

interface RuleLoaderIfc;
  method RuleLoadFields parseWord(Bit#(512) inputWord);
endinterface

function RuleLoadFields decodeRuleLoadFields(Bit#(512) inputWord);
  return RuleLoadFields {
    payload64: inputWord[63:0],
    rule64: inputWord[127:64],
    patternLen: inputWord[135:128],
    ruleId: inputWord[167:136],
    ruleProto: inputWord[359:352],
    portGroupId: inputWord[183:168],
    portGroupType: inputWord[185:184],
    groupPortSingle: inputWord[201:186],
    groupRangeStart: inputWord[217:202],
    groupRangeEnd: inputWord[233:218],
    nfFingerprint: inputWord[249:234],
    nfEnable: unpack(inputWord[250]),
    portDirection: inputWord[252:251]
  };
endfunction

module mkRuleLoader(RuleLoaderIfc);
  method RuleLoadFields parseWord(Bit#(512) inputWord);
    return decodeRuleLoadFields(inputWord);
  endmethod
endmodule

endpackage: RuleLoader
