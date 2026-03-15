import FIFO::*;
import Vector::*;

// TrafficManager: Decides which packets need full matching after Header Matching
// Based on Pigasus paper Figure 8 - sits between Header Matching and NFPSM
//
// After Header Matching checks port groups, Traffic Manager:
// 1. Collects rule IDs that matched both FPSM and header filters
// 2. Decides if packet needs Non-Fast-Pattern String Matching (NFPSM)
// 3. Forwards (packet, ruleIds) to NFPSM or releases clean packets
//
// In Pigasus architecture:
// - Packets with 0 rule IDs → released (no match)
// - Packets with 1+ rule IDs → sent to NFPSM for full checking

typedef Bit#(16) RuleId;
typedef Bit#(8) LaneIdx;    // Which FPSM lane (0-31) matched
typedef Bit#(8) MatchLen;   // Length of matched pattern (1-8 bytes)

// Result of header matching for one match
typedef struct {
    Bool valid;          // True if this match passed header filtering
    LaneIdx laneIdx;     // Which FPSM lane matched
    MatchLen matchLen;   // Pattern length
    RuleId ruleId;       // Rule ID from RuleTable
} HeaderMatchResult deriving (Bits, Eq);

// Packet decision after header matching
typedef struct {
    Bool needsNFPSM;              // True if packet needs full matching
    Bit#(3) numRules;             // Number of rule IDs (0-8)
    Vector#(8, RuleId) ruleIds;   // Rule IDs that need full checking
} TrafficDecision deriving (Bits, Eq);

interface TrafficManagerIfc;
    // Input: Results from Header Matching stage (up to 8 matches per packet)
    method Action putHeaderResults(Vector#(8, HeaderMatchResult) results);
    
    // Output: Decision for this packet
    method ActionValue#(TrafficDecision) getDecision();
    
    // Statistics
    method Bit#(32) getCleanPackets();      // Packets released (0 matches)
    method Bit#(32) getNFPSMPackets();      // Packets sent to NFPSM (1+ matches)
endinterface

module mkTrafficManager(TrafficManagerIfc);
    FIFO#(TrafficDecision) decisionQ <- mkFIFO;
    
    // Statistics counters
    Reg#(Bit#(32)) cleanPacketCount <- mkReg(0);   // Packets with 0 rule matches
    Reg#(Bit#(32)) nfpsmPacketCount <- mkReg(0);   // Packets sent to NFPSM
    
    method Action putHeaderResults(Vector#(8, HeaderMatchResult) results);
        // Count how many valid matches passed header filtering
        Bit#(3) validCount = 0;
        Vector#(8, RuleId) ruleIds = replicate(0);
        
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (results[i].valid) begin
                ruleIds[validCount] = results[i].ruleId;
                validCount = validCount + 1;
            end
        end
        
        // Make decision
        TrafficDecision decision = TrafficDecision {
            needsNFPSM: (validCount > 0),
            numRules: validCount,
            ruleIds: ruleIds
        };
        
        decisionQ.enq(decision);
        
        // Update statistics
        if (validCount == 0) begin
            cleanPacketCount <= cleanPacketCount + 1;
        end else begin
            nfpsmPacketCount <= nfpsmPacketCount + 1;
        end
    endmethod
    
    method ActionValue#(TrafficDecision) getDecision();
        decisionQ.deq;
        return decisionQ.first;
    endmethod
    
    method Bit#(32) getCleanPackets() = cleanPacketCount;
    method Bit#(32) getNFPSMPackets() = nfpsmPacketCount;
endmodule

