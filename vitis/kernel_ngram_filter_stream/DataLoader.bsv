package DataLoader;

import FIFOF::*;
import BitmapUram::*;
import GramMatcher::*;
import ExactPatternTable::*;
import PortOffsetMatcher::*;
import Priority::*;

typedef enum {
    DLIdle,
    DLHeader,
    DLBm0S1,
    DLBm0S2,
    DLBm1,
    DLGhtFetch,
    DLGhtUnpack,
    DLGhtAck,
    DLPattern,
    DLConstraintFetch,
    DLConstraintUnpack,
    DLPriorityFetch,
    DLPriorityUnpack,
    DLBloomFetch,
    DLBloomUnpack,
    DLDone
} DLState deriving (Bits, Eq, FShow);

// Core interface: word-push model, no knowledge of word source (AXI4 / slave / stream).
// All read requests are relative byte offsets from the DB base supplied by the caller.
interface DataLoaderCoreIfc;
    method Action startLoad(Bit#(32) dbBytes);
    method Bool   canAcceptWord;
    method Action putWord(Bit#(512) word);
    method Bool   loadDone;
    // Relative (offset, size) pairs the caller must fetch and push back via putWord.
    method ActionValue#(Tuple2#(Bit#(32), Bit#(32))) readReqRel;
endinterface

module mkDataLoaderCore#(
    BitmapUramIfc        bm0_s1,
    BitmapUramIfc        bm0_s2,
    BitmapUramIfc        bm1,
    GramMatcherIfc       gram,
    ExactPatternTableIfc patTable,
    PortOffsetMatcherIfc portMatcher,
    PriorityIfc          prioStage
)(DataLoaderCoreIfc);

    // readReqQ carries (relativeOffset, byteCount); both Bit#(32).
    FIFOF#(Tuple2#(Bit#(32), Bit#(32))) readReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(4);

    Reg#(DLState)  state      <- mkReg(DLIdle);
    Reg#(Bit#(32)) patCount   <- mkReg(0);
    Reg#(Bit#(32)) ghtCount   <- mkReg(0);
    Reg#(Bit#(32)) ruledbOff  <- mkReg(0);
    Reg#(Bit#(32)) portlocOff <- mkReg(0);
    Reg#(Bit#(32)) priorityOff<- mkReg(0);
    Reg#(Bit#(32)) bloomOff   <- mkReg(0);
    Reg#(Bit#(32)) wordIdx    <- mkReg(0);
    Reg#(Bool)     done       <- mkReg(False);

    Reg#(Bit#(512)) curWord  <- mkRegU;
    Reg#(Bit#(3))   subIdx   <- mkReg(0);
    Reg#(Bit#(32))  ghtDone  <- mkReg(0);

    Reg#(Bit#(32)) portWord  <- mkReg(0);
    Reg#(Bit#(4))  portSubIdx<- mkReg(0);
    Reg#(Bit#(32)) prioDone  <- mkReg(0);
    Reg#(Bit#(6))  prioSubIdx<- mkReg(0);

    Reg#(Bit#(32)) bloomWord <- mkReg(0);
    Reg#(Bit#(3))  bloomSub  <- mkReg(0);

    // GHT entry bit layout (128 bits per entry, 4 entries per 512-bit word):
    //   [31: 0]   gram32 key (18-bit key zero-padded to 32)
    //   [47:32]   ruleId
    //   [55:48]   pre (signed)
    //   [63:56]   post (signed)
    //   [71:64]   len
    //   [72]      stage2 flag
    //   [90:73]   nextGramKey (18 bits, valid when stage2=1)
    //   [114:91]  anchorGram (folded full 3-byte anchor)
    //   [119:115] padding
    //   [120]     is_first (cuckoo insert gate; matches gen.c sort grouping)
    //   [121]     is_last  (chain follow terminator)
    //   [127:122] padding
    function RuleInfo unpackRuleInfo(Bit#(128) raw);
        return RuleInfo {
            ruleId:      raw[47:32],
            pre:         unpack(raw[55:48]),
            post:        unpack(raw[63:56]),
            len:         raw[71:64],
            stage2:      (raw[72] == 1),
            nextGramKey: raw[90:73],
            anchorGram:  raw[114:91],
            pad:         0
        };
    endfunction

    rule doHeader(state == DLHeader && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        ghtCount   <= w[127:96];
        patCount   <= w[159:128];
        ruledbOff  <= w[191:160];
        portlocOff <= w[223:192];
        priorityOff<= w[255:224];
        bloomOff   <= w[287:256];
        $display("DL header ght=%0d pat=%0d ruledbOff=%0d portlocOff=%0d priorityOff=%0d bloomOff=%0d",
                 w[127:96], w[159:128], w[191:160], w[223:192], w[255:224], w[287:256]);
        readReqQ.enq(tuple2(32'd64, 32'd32768));
        wordIdx <= 0;
        state   <= DLBm0S1;
    endrule

    rule doBm0S1(state == DLBm0S1 && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        bm0_s1.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm0_s1 done");
            readReqQ.enq(tuple2(32'd32832, 32'd32768));
            wordIdx <= 0;
            state   <= DLBm0S2;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule doBm0S2(state == DLBm0S2 && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        bm0_s2.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm0_s2 done");
            readReqQ.enq(tuple2(32'd65600, 32'd32768));
            wordIdx <= 0;
            state   <= DLBm1;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule doBm1(state == DLBm1 && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        bm1.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm1 done");
            Bit#(32) ghtBytes = ((ghtCount + 3) / 4) * 64;
            readReqQ.enq(tuple2(32'd98368, ghtBytes));
            wordIdx <= 0;
            ghtDone <= 0;
            subIdx  <= 0;
            state   <= DLGhtFetch;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule doGhtFetch(state == DLGhtFetch && wordQ.notEmpty && ghtDone < ghtCount);
        let w = wordQ.first; wordQ.deq;
        curWord <= w;
        subIdx  <= 0;
        state   <= DLGhtUnpack;
    endrule

    rule doGhtUnpack(state == DLGhtUnpack);
        if (ghtDone < ghtCount) begin
            RuleInfo info    = unpackRuleInfo(curWord[127:0]);
            Bit#(32) gram32  = curWord[31:0];
            Bool     isFirst = (curWord[120] == 1);
            Bool     isLast  = (curWord[121] == 1);
            gram.loadEntry(gram32, truncate(ghtDone), info, isFirst, isLast);
            state <= DLGhtAck;
        end else begin
            readReqQ.enq(tuple2(ruledbOff, patCount * 64));
            wordIdx <= 0;
            state   <= DLPattern;
        end
    endrule

    rule doGhtAck(state == DLGhtAck);
        let ok <- gram.insertAck;
        ghtDone <= ghtDone + 1;
        curWord <= curWord >> 128;
        subIdx  <= subIdx + 1;
        if (subIdx == 3 || ghtDone + 1 >= ghtCount) begin
            if (ghtDone + 1 < ghtCount)
                state <= DLGhtFetch;
            else begin
                $display("DL GHT done");
                readReqQ.enq(tuple2(ruledbOff, patCount * 64));
                wordIdx <= 0;
                state   <= DLPattern;
            end
        end else begin
            state <= DLGhtUnpack;
        end
    endrule

    rule doPattern(state == DLPattern && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        patTable.writePattern(truncate(wordIdx), w);
        wordIdx <= wordIdx + 1;
        if (wordIdx + 1 >= patCount) begin
            $display("DL patterns done");
            Bit#(32) cbytes = ((patCount + 7) >> 3) * 64;
            readReqQ.enq(tuple2(portlocOff, cbytes));
            portWord   <= 0;
            portSubIdx <= 0;
            state      <= DLConstraintFetch;
        end
    endrule

    rule doConstraintFetch(state == DLConstraintFetch && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        curWord    <= w;
        portSubIdx <= 0;
        state      <= DLConstraintUnpack;
    endrule

    // 8 x 64-bit constraint entries per 512-bit line, indexed by ruleId.
    rule doConstraintUnpack(state == DLConstraintUnpack);
        portMatcher.writeConstraint(truncate(portWord), curWord[63:0]);
        curWord <= curWord >> 64;
        if (portSubIdx == 7) begin
            portSubIdx <= 0;
            if (portWord + 1 >= patCount) begin
                if (priorityOff != 0 && patCount != 0) begin
                    $display("DL constraints done, loading priority");
                    Bit#(32) prioBytes = ((patCount + 63) >> 6) << 6;
                    readReqQ.enq(tuple2(priorityOff, prioBytes));
                    prioDone   <= 0;
                    state      <= DLPriorityFetch;
                end else begin
                    $display("DL constraints done, loading bloom");
                    readReqQ.enq(tuple2(bloomOff, 32'd32768));
                    bloomWord <= 0;
                    state     <= DLBloomFetch;
                end
            end else begin
                portWord <= portWord + 1;
                state    <= DLConstraintFetch;
            end
        end else begin
            portSubIdx <= portSubIdx + 1;
            portWord   <= portWord + 1;
        end
    endrule

    rule doPriorityFetch(state == DLPriorityFetch && wordQ.notEmpty && prioDone < patCount);
        let w = wordQ.first; wordQ.deq;
        curWord    <= w;
        prioSubIdx <= 0;
        state      <= DLPriorityUnpack;
    endrule

    rule doPriorityUnpack(state == DLPriorityUnpack);
        Bit#(2) prio = curWord[1:0];
        prioStage.writePriority(truncate(prioDone), prio);
        curWord <= curWord >> 8;

        if (prioSubIdx == 63 || prioDone + 1 >= patCount) begin
            prioDone <= prioDone + 1;
            prioSubIdx <= 0;
            if (prioDone + 1 < patCount) begin
                state <= DLPriorityFetch;
            end else begin
                $display("DL priority done, loading bloom");
                readReqQ.enq(tuple2(bloomOff, 32'd32768));
                bloomWord <= 0;
                state     <= DLBloomFetch;
            end
        end else begin
            prioDone   <= prioDone + 1;
            prioSubIdx <= prioSubIdx + 1;
        end
    endrule

    // Bloom section: 512 lines x 64B = 32KB.  Each 512-bit line carries 8
    // consecutive 64-bit bloom words -> BRAM addrs [8*line .. 8*line+7].
    rule doBloomFetch(state == DLBloomFetch && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        curWord  <= w;
        bloomSub <= 0;
        state    <= DLBloomUnpack;
    endrule

    rule doBloomUnpack(state == DLBloomUnpack);
        Bit#(12) addr = truncate({bloomWord[8:0], bloomSub});
        gram.writeBloom(addr, curWord[63:0]);
        curWord <= curWord >> 64;
        if (bloomSub == 7) begin
            bloomSub <= 0;
            if (bloomWord == 511) begin
                $display("DL bloom done");
                done  <= True;
                state <= DLDone;
            end else begin
                bloomWord <= bloomWord + 1;
                state     <= DLBloomFetch;
            end
        end else begin
            bloomSub <= bloomSub + 1;
        end
    endrule

    method Action startLoad(Bit#(32) dbBytes) if (state == DLIdle || state == DLDone);
        done  <= False;
        readReqQ.enq(tuple2(32'd0, 32'd64));
        state <= DLHeader;
    endmethod

    method Bool canAcceptWord = wordQ.notFull;

    method Action putWord(Bit#(512) word);
        wordQ.enq(word);
    endmethod

    method Bool loadDone = done;

    method ActionValue#(Tuple2#(Bit#(32), Bit#(32))) readReqRel;
        let r = readReqQ.first; readReqQ.deq; return r;
    endmethod

endmodule

// AXI4-read adapter: wraps DataLoaderCore, converts relative offsets to absolute (+ dbBase).
interface DataLoaderIfc;
    method Action startLoad(Bit#(64) dbBase, Bit#(32) dbBytes);
    method Bool   loadDone;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
    method Action readWord(Bit#(512) word);
endinterface

module mkDataLoader#(
    BitmapUramIfc        bm0_s1,
    BitmapUramIfc        bm0_s2,
    BitmapUramIfc        bm1,
    GramMatcherIfc       gram,
    ExactPatternTableIfc patTable,
    PortOffsetMatcherIfc portMatcher,
    PriorityIfc          prioStage
)(DataLoaderIfc);

    DataLoaderCoreIfc core <- mkDataLoaderCore(bm0_s1, bm0_s2, bm1,
                                               gram, patTable, portMatcher, prioStage);

    Reg#(Bit#(64)) baseAddr_r <- mkRegU;
    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) absReqQ <- mkFIFOF;

    rule relayReadReq;
        let {relOff, bytes} <- core.readReqRel;
        absReqQ.enq(tuple2(baseAddr_r + zeroExtend(relOff), zeroExtend(bytes)));
    endrule

    method Action startLoad(Bit#(64) dbBase, Bit#(32) dbBytes);
        baseAddr_r <= dbBase;
        core.startLoad(dbBytes);
    endmethod

    method Bool loadDone = core.loadDone;

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
        let r = absReqQ.first; absReqQ.deq; return r;
    endmethod

    method Action readWord(Bit#(512) word) if (core.canAcceptWord);
        core.putWord(word);
    endmethod

endmodule

endpackage
