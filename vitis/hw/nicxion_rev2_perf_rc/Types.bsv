package Types;

typedef 8 NEpoch;                          // packets in flight (one per epoch)
typedef Bit#(TLog#(NEpoch)) Epoch;
typedef Bit#(32) PktIdx;                   // host packet sequence number
typedef Bit#(16) RuleId;                   // rule id from the rule file
typedef Bit#(18) GramKey;                  // bitmap/cuckoo key of a 3-byte gram
typedef Bit#(24) AnchorGram;               // raw 3-byte gram

function Bit#(8) foldCase(Bit#(8) b) =
    ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;

endpackage
