package Types;

typedef 8 NEpoch;                          // packets in flight (one per epoch)
typedef Bit#(TLog#(NEpoch)) Epoch;
typedef Bit#(32) PktIdx;                   // host packet sequence number
typedef Bit#(16) RuleId;                   // rule id from the rule file

endpackage
