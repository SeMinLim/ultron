package DbStreamLoader;

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
    rule feedDbWord;   // putWord carries wordQ's notFull implicitly
        let beat <- dbStream.get;
        core.putWord(tpl_1(beat));
    endrule

    method Action startLoad(Bit#(32) dbBytes);
        core.startLoad(dbBytes);
    endmethod

    method Bool loadDone = core.loadDone;
endmodule

endpackage
