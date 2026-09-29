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

interface DataLoaderCoreIfc;
    method Action startLoad(Bit#(32) dbBytes);
    method Bool   canAcceptWord;
    method Action putWord(Bit#(512) word);
    method Bool   loadDone;
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

    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(4);
    FIFOF#(Bit#(512))                   wordQ2   <- mkFIFOF;

    Reg#(DLState)  state      <- mkReg(DLIdle);
    Reg#(Bit#(32)) patCount   <- mkRegU;
    Reg#(Bit#(32)) ghtCount   <- mkRegU;
    Reg#(Bit#(32)) ruledbOff  <- mkRegU;
    Reg#(Bit#(32)) portlocOff <- mkRegU;
    Reg#(Bit#(32)) priorityOff<- mkRegU;
    Reg#(Bit#(32)) bloomOff   <- mkRegU;
    Reg#(Bit#(32)) wordIdx    <- mkRegU;
    Reg#(Bool)     done       <- mkReg(False);

    Reg#(Bit#(512)) curWord  <- mkRegU;
    Reg#(Bit#(3))   subIdx   <- mkRegU;
    Reg#(Bit#(32))  ghtDone  <- mkRegU;

    Reg#(Bit#(32)) portWord  <- mkRegU;
    Reg#(Bit#(4))  portSubIdx<- mkRegU;
    Reg#(Bit#(32)) prioDone  <- mkRegU;
    Reg#(Bit#(6))  prioSubIdx<- mkRegU;

    Reg#(Bit#(32)) bloomWord <- mkRegU;
    Reg#(Bit#(3))  bloomSub  <- mkRegU;

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

    rule stageWord;
        wordQ2.enq(wordQ.first); wordQ.deq;
    endrule

    rule loadHeader(state == DLHeader);
        let w = wordQ2.first; wordQ2.deq;
        ghtCount   <= w[127:96];
        patCount   <= w[159:128];
        ruledbOff  <= w[191:160];
        portlocOff <= w[223:192];
        priorityOff<= w[255:224];
        bloomOff   <= w[287:256];
        $display("DL header ght=%0d pat=%0d ruledbOff=%0d portlocOff=%0d priorityOff=%0d bloomOff=%0d",
                 w[127:96], w[159:128], w[191:160], w[223:192], w[255:224], w[287:256]);
        wordIdx <= 0;
        state   <= DLBm0S1;
    endrule

    rule loadBm0S1(state == DLBm0S1);
        let w = wordQ2.first; wordQ2.deq;
        bm0_s1.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm0_s1 done");
            wordIdx <= 0;
            state   <= DLBm0S2;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule loadBm0S2(state == DLBm0S2);
        let w = wordQ2.first; wordQ2.deq;
        bm0_s2.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm0_s2 done");
            wordIdx <= 0;
            state   <= DLBm1;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule loadBm1(state == DLBm1);
        let w = wordQ2.first; wordQ2.deq;
        bm1.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm1 done");
            wordIdx <= 0;
            ghtDone <= 0;
            subIdx  <= 0;
            state   <= DLGhtFetch;
        end else begin
            wordIdx <= wordIdx + 1;
        end
    endrule

    rule loadGhtFetch(state == DLGhtFetch && ghtDone < ghtCount);
        let w = wordQ2.first; wordQ2.deq;
        curWord <= w;
        subIdx  <= 0;
        state   <= DLGhtUnpack;
    endrule

    rule loadGhtUnpack(state == DLGhtUnpack);
        if (ghtDone < ghtCount) begin
            RuleInfo info    = unpackRuleInfo(curWord[127:0]);
            Bit#(32) gram32  = curWord[31:0];
            Bool     isFirst = (curWord[120] == 1);
            Bool     isLast  = (curWord[121] == 1);
            gram.loadEntry(gram32, truncate(ghtDone), info, isFirst, isLast);
            state <= DLGhtAck;
        end else begin
            wordIdx <= 0;
            state   <= DLPattern;
        end
    endrule

    rule loadGhtAck(state == DLGhtAck);
        let ok <- gram.insertAck;
        ghtDone <= ghtDone + 1;
        curWord <= curWord >> 128;
        subIdx  <= subIdx + 1;
        if (subIdx == 3 || ghtDone + 1 >= ghtCount) begin
            if (ghtDone + 1 < ghtCount)
                state <= DLGhtFetch;
            else begin
                $display("DL GHT done");
                wordIdx <= 0;
                state   <= DLPattern;
            end
        end else begin
            state <= DLGhtUnpack;
        end
    endrule

    rule loadPattern(state == DLPattern);
        let w = wordQ2.first; wordQ2.deq;
        patTable.writePattern(truncate(wordIdx), w);
        wordIdx <= wordIdx + 1;
        if (wordIdx + 1 >= patCount) begin
            $display("DL patterns done");
            portWord   <= 0;
            portSubIdx <= 0;
            state      <= DLConstraintFetch;
        end
    endrule

    rule loadConstraintFetch(state == DLConstraintFetch);
        let w = wordQ2.first; wordQ2.deq;
        curWord    <= w;
        portSubIdx <= 0;
        state      <= DLConstraintUnpack;
    endrule

    rule loadConstraintUnpack(state == DLConstraintUnpack);
        portMatcher.writeConstraint(truncate(portWord), curWord[63:0]);
        curWord <= curWord >> 64;
        if (portSubIdx == 7) begin
            portSubIdx <= 0;
            if (portWord + 1 >= patCount) begin
                if (priorityOff != 0 && patCount != 0) begin
                    $display("DL constraints done, loading priority");
                    prioDone   <= 0;
                    state      <= DLPriorityFetch;
                end else begin
                    $display("DL constraints done, loading bloom");
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

    rule loadPriorityFetch(state == DLPriorityFetch && prioDone < patCount);
        let w = wordQ2.first; wordQ2.deq;
        curWord    <= w;
        prioSubIdx <= 0;
        state      <= DLPriorityUnpack;
    endrule

    rule loadPriorityUnpack(state == DLPriorityUnpack);
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
                bloomWord <= 0;
                state     <= DLBloomFetch;
            end
        end else begin
            prioDone   <= prioDone + 1;
            prioSubIdx <= prioSubIdx + 1;
        end
    endrule

    rule loadBloomFetch(state == DLBloomFetch);
        let w = wordQ2.first; wordQ2.deq;
        curWord  <= w;
        bloomSub <= 0;
        state    <= DLBloomUnpack;
    endrule

    rule loadBloomUnpack(state == DLBloomUnpack);
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
        state <= DLHeader;
    endmethod

    method Bool canAcceptWord = wordQ.notFull;

    method Action putWord(Bit#(512) word);
        wordQ.enq(word);
    endmethod

    method Bool loadDone = done;


endmodule


endpackage
