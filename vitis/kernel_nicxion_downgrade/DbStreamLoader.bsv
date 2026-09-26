package DbStreamLoader;

// DB Master->Slave (Req 1): the CPU/host PUSHES the rule DB into the kernel over
// an AXI4-Stream slave port, instead of the kernel mastering reads from memory.
// Wraps the Track-A DataLoaderCore (push entry point putWord), feeding it words
// straight off the stream. The blob is contiguous in FSM-consumption order, so a
// linear push delivers the exact word sequence the section FSM expects; the
// FSM's readReqRel requests are unused here and simply drained.

import FIFOF::*;

import BitmapUram::*;
import GramMatcher::*;
import ExactPatternTable::*;
import PortOffsetMatcher::*;
import Priority::*;

import DataLoader::*;   // DataLoaderCoreIfc, mkDataLoaderCore
import AxiStream::*;    // AxiStreamSlaveIfc

interface DbStreamLoaderIfc;
    method Action startLoad(Bit#(32) dbBytes);
    method Bool   loadDone;
endinterface

module mkDbStreamLoader#(
    BitmapUramIfc          bm0_s1,
    BitmapUramIfc          bm0_s2,
    BitmapUramIfc          bm1,
    GramMatcherIfc         gram,
    ExactPatternTableIfc   patTable,
    PortOffsetMatcherIfc   portMatcher,
    PriorityIfc            prioStage,
    AxiStreamSlaveIfc#(512) dbStream
)(DbStreamLoaderIfc);

    DataLoaderCoreIfc core <- mkDataLoaderCore(bm0_s1, bm0_s2, bm1,
                                               gram, patTable, portMatcher, prioStage);

    // Push each DB stream beat into the section-loading FSM.
    rule feedDbWord(core.canAcceptWord);
        let beat <- dbStream.get;
        core.putWord(tpl_1(beat));
    endrule

    // Pull model emits relative section read requests; in push mode no fetch
    // happens, so drain them to keep the FSM from blocking on a full request FIFO.
    rule drainReadReq;
        let r <- core.readReqRel;
    endrule

    method Action startLoad(Bit#(32) dbBytes);
        core.startLoad(dbBytes);
    endmethod

    method Bool loadDone = core.loadDone;
endmodule

endpackage
