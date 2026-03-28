package TrafficManager;

import FIFO::*;
import Vector::*;
import PacketParserTypes::*;

typedef Bit#(16) RuleId;
typedef Bit#(8) LaneIdx;
typedef Bit#(8) MatchLen;

typedef struct {
    Bool valid;
    LaneIdx laneIdx;
    MatchLen matchLen;
    RuleId ruleId;
} HeaderMatchResult deriving (Bits, Eq);

typedef struct {
    Bool needsNFPSM;
    Bit#(3) numRules;
    Vector#(8, RuleId) ruleIds;
} TrafficDecision deriving (Bits, Eq);

interface TrafficManagerIfc;

    method Action putHeaderResults(Vector#(8, HeaderMatchResult) results,
                                   PacketMeta meta);
    

    method ActionValue#(Tuple2#(TrafficDecision, PacketMeta)) getDecision();
    

    method Bit#(32) getCleanPackets();
    method Bit#(32) getNFPSMPackets();
endinterface

module mkTrafficManager(TrafficManagerIfc);
    FIFO#(Tuple2#(TrafficDecision, PacketMeta)) decisionQ <- mkFIFO;
    

    Reg#(Bit#(32)) cleanPacketCount <- mkReg(0);
    Reg#(Bit#(32)) nfpsmPacketCount <- mkReg(0);
    
    method Action putHeaderResults(Vector#(8, HeaderMatchResult) results,
                                   PacketMeta meta);

        Bit#(3) validCount = 0;
        Vector#(8, RuleId) ruleIds = replicate(0);
        
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (results[i].valid) begin
                ruleIds[validCount] = results[i].ruleId;
                validCount = validCount + 1;
            end
        end
        

        TrafficDecision decision = TrafficDecision {
            needsNFPSM: (validCount > 0),
            numRules: validCount,
            ruleIds: ruleIds
        };
        
        decisionQ.enq(tuple2(decision, meta));
        

        if (validCount == 0) begin
            cleanPacketCount <= cleanPacketCount + 1;
        end else begin
            nfpsmPacketCount <= nfpsmPacketCount + 1;
        end
    endmethod
    
    method ActionValue#(Tuple2#(TrafficDecision, PacketMeta)) getDecision();
        let decision = decisionQ.first;
        decisionQ.deq;
        return decision;
    endmethod
    
    method Bit#(32) getCleanPackets() = cleanPacketCount;
    method Bit#(32) getNFPSMPackets() = nfpsmPacketCount;
endmodule

endpackage: TrafficManager
