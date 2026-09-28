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
    DLPortBitmap,
    DLPortWinFetch,
    DLPortWinUnpack,
    DLPortSmallFetch,
    DLPortSmallUnpack,
    DLPriorityFetch,
    DLPriorityUnpack,
    DLDone
} DLState deriving (Bits, Eq, FShow);

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

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) readReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(4);

    Reg#(DLState)  state      <- mkReg(DLIdle);
    Reg#(Bit#(64)) baseAddr   <- mkRegU;
    Reg#(Bit#(32)) patCount   <- mkReg(0);
    Reg#(Bit#(32)) ghtCount   <- mkReg(0);
    Reg#(Bit#(32)) ruledbOff  <- mkReg(0);
    Reg#(Bit#(32)) portlocOff <- mkReg(0);
    Reg#(Bit#(32)) priorityOff<- mkReg(0);
    Reg#(Bit#(32)) wordIdx    <- mkReg(0);
    Reg#(Bool)     done       <- mkReg(False);

    Reg#(Bit#(512)) curWord  <- mkRegU;
    Reg#(Bit#(3))   subIdx   <- mkReg(0);
    Reg#(Bit#(32))  ghtDone  <- mkReg(0);

    Reg#(Bit#(32)) portWord  <- mkReg(0);
    Reg#(Bit#(4))  portSubIdx<- mkReg(0);
    Reg#(Bit#(32)) prioDone  <- mkReg(0);
    Reg#(Bit#(6))  prioSubIdx<- mkReg(0);

    // GHT entry layout: gram[31:0], ruleId[47:32], pre[55:48],
    // post[63:56], len[71:64], stage2[72], nextGram[90:73],
    // anchorGram[114:91], isFirst[120], isLast[121].
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
        $display("DL header ght=%0d pat=%0d ruledbOff=%0d portlocOff=%0d priorityOff=%0d",
                 w[127:96], w[159:128], w[191:160], w[223:192], w[255:224]);
        readReqQ.enq(tuple2(baseAddr + 64, 32 * 1024));
        wordIdx <= 0;
        state   <= DLBm0S1;
    endrule

    rule doBm0S1(state == DLBm0S1 && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        bm0_s1.writeWord(truncate(wordIdx), w);
        if (wordIdx == 511) begin
            $display("DL bm0_s1 done");
            readReqQ.enq(tuple2(baseAddr + 64 + 32*1024, 32*1024));
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
            readReqQ.enq(tuple2(baseAddr + 64 + 64*1024, 32*1024));
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
            Bit#(64) ghtBytes = zeroExtend((ghtCount + 3) / 4) * 64;
            readReqQ.enq(tuple2(baseAddr + 64 + 96*1024, ghtBytes));
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
            Bit#(64) patOff = zeroExtend(ruledbOff);
            readReqQ.enq(tuple2(baseAddr + patOff, zeroExtend(patCount) * 64));
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
                Bit#(64) patOff = zeroExtend(ruledbOff);
                readReqQ.enq(tuple2(baseAddr + patOff, zeroExtend(patCount) * 64));
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
            Bit#(64) plOff = zeroExtend(portlocOff);
            readReqQ.enq(tuple2(baseAddr + plOff, 512 * 64));
            portWord <= 0;
            state    <= DLPortBitmap;
        end
    endrule

    rule doPortBitmap(state == DLPortBitmap && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        Bit#(2) tbl  = truncate(portWord >> 7);
        Bit#(7) addr = truncate(portWord);
        portMatcher.writeBitmap(tbl, addr, w);
        if (portWord == 511) begin
            $display("DL port bitmap done");
            Bit#(64) plOff = zeroExtend(portlocOff) + 512 * 64;
            readReqQ.enq(tuple2(baseAddr + plOff, 256 * 64));
            portWord    <= 0;
            portSubIdx  <= 0;
            state       <= DLPortWinFetch;
        end else begin
            portWord <= portWord + 1;
        end
    endrule

    rule doPortWinFetch(state == DLPortWinFetch && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        curWord    <= w;
        portSubIdx <= 0;
        state      <= DLPortWinUnpack;
    endrule

    rule doPortWinUnpack(state == DLPortWinUnpack);
        Bit#(32) entry = curWord[31:0];
        Bit#(2)  tbl   = truncate(portWord >> 6);
        Bit#(10) addr  = truncate({portWord[5:0], portSubIdx});
        portMatcher.writeWindow(tbl, addr, entry);
        curWord <= curWord >> 32;
        if (portSubIdx == 15) begin
            portSubIdx <= 0;
            if (portWord == 255) begin
                $display("DL port windows done");
                Bit#(64) plOff = zeroExtend(portlocOff) + 512*64 + 256*64;
                readReqQ.enq(tuple2(baseAddr + plOff, 32 * 64));
                portWord   <= 0;
                state      <= DLPortSmallFetch;
            end else begin
                portWord <= portWord + 1;
                state <= DLPortWinFetch;
            end
        end else begin
            portSubIdx <= portSubIdx + 1;
        end
    endrule

    rule doPortSmallFetch(state == DLPortSmallFetch && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        curWord    <= w;
        portSubIdx <= 0;
        state      <= DLPortSmallUnpack;
    endrule

    rule doPortSmallUnpack(state == DLPortSmallUnpack);
        Bit#(32) entry = curWord[31:0];
        Bit#(8)  addr  = truncate({portWord[3:0], portSubIdx});
        if (portWord < 16)
            portMatcher.writeIpProto(addr, entry);
        else
            portMatcher.writeIcmp(addr, entry);
        curWord <= curWord >> 32;
        if (portSubIdx == 15) begin
            portWord   <= portWord + 1;
            portSubIdx <= 0;
            if (portWord == 31) begin
                if (priorityOff != 0 && patCount != 0) begin
                    Bit#(64) prioBytes = zeroExtend(((patCount + 63) >> 6) << 6);
                    readReqQ.enq(tuple2(baseAddr + zeroExtend(priorityOff), prioBytes));
                    prioDone   <= 0;
                    state      <= DLPriorityFetch;
                end else begin
                    $display("DL done");
                    done  <= True;
                    state <= DLDone;
                end
            end else begin
                state <= DLPortSmallFetch;
            end
        end else begin
            portSubIdx <= portSubIdx + 1;
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
                $display("DL priority done");
                done  <= True;
                state <= DLDone;
            end
        end else begin
            prioDone   <= prioDone + 1;
            prioSubIdx <= prioSubIdx + 1;
        end
    endrule

    method Action startLoad(Bit#(64) dbBase, Bit#(32) dbBytes) if (state == DLIdle || state == DLDone);
        baseAddr <= dbBase;
        done     <= False;
        readReqQ.enq(tuple2(dbBase, 64));
        state    <= DLHeader;
    endmethod

    method Bool loadDone = done;

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
        let r = readReqQ.first; readReqQ.deq; return r;
    endmethod

    method Action readWord(Bit#(512) word);
        wordQ.enq(word);
    endmethod

endmodule

endpackage
