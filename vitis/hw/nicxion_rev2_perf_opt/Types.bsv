package Types;

typedef 8 NEpoch;                          // packets in flight (one per epoch)
typedef Bit#(TLog#(NEpoch)) Epoch;
typedef Bit#(32) PktIdx;                   // host packet sequence number
typedef Bit#(16) RuleId;                   // rule id from the rule file

// ASCII case fold (A-Z -> a-z); the n-gram front end and exact match must agree.
function Bit#(8) foldCase(Bit#(8) b) =
    ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;

endpackage
