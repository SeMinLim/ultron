package DataLoader;

import FIFO::*;
import FIFOF::*;
import BitmapUram::*;
import GramIdTable::*;
import GramMatcher::*;
import ExactPatternTable::*;
import PortOffsetMatcher::*;

typedef enum {
    DLIdle,
    DLHeader,
    DLBitmap,
    DLGhtFetch,
    DLGhtUnpack,
    DLGhtInsert,
    DLGhtAck,
    DLPattern,
    DLPortBitmap,
    DLPortWinFetch,
    DLPortWinUnpack,
    DLPortSmallFetch,
    DLPortSmallUnpack,
    DLDone
} DLState deriving (Bits, Eq, FShow);

interface DataLoaderIfc;
    method Action startLoad(Bit#(64) dbBase, Bit#(32) dbBytes);
    method Bool   loadDone;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) readReq;
    method Action readWord(Bit#(512) word);
endinterface

module mkDataLoader#(
    BitmapUramIfc        bitmap,
    GramMatcherIfc       gram,
    ExactPatternTableIfc patTable,
    PortOffsetMatcherIfc portMatcher
)(DataLoaderIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) readReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   wordQ    <- mkSizedFIFOF(4);

    Reg#(DLState)  state      <- mkReg(DLIdle);
    Reg#(Bit#(64)) baseAddr   <- mkRegU;
    Reg#(Bit#(32)) patCount   <- mkReg(0);
    Reg#(Bit#(32)) ghtCount   <- mkReg(0);
    Reg#(Bit#(32)) ruledbOff  <- mkReg(0);
    Reg#(Bit#(32)) portlocOff <- mkReg(0);
    Reg#(Bit#(32)) wordIdx    <- mkReg(0);
    Reg#(Bool)     done       <- mkReg(False);

    Reg#(Bit#(512)) curWord  <- mkRegU;
    Reg#(Bit#(3))   subIdx   <- mkReg(0);
    Reg#(Bit#(32))  ghtDone  <- mkReg(0);

    Reg#(Bit#(32)) portWord  <- mkReg(0);
    Reg#(Bit#(5))  portSubIdx<- mkReg(0);

    function RuleInfo unpackRuleInfo(Bit#(128) raw);
        return RuleInfo {
            ruleId: raw[47:32],
            pre:    unpack(raw[55:48]),
            post:   unpack(raw[63:56]),
            len:    raw[71:64]
        };
    endfunction

    rule doHeader(state == DLHeader && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        ghtCount   <= w[127:96];
        patCount   <= w[159:128];
        ruledbOff  <= w[191:160];
        portlocOff <= w[223:192];
        readReqQ.enq(tuple2(baseAddr + 64, 256 * 1024));
        wordIdx <= 0;
        state   <= DLBitmap;
    endrule

    rule doBitmap(state == DLBitmap && wordQ.notEmpty);
        let w = wordQ.first; wordQ.deq;
        bitmap.writeWord(truncate(wordIdx), w);
        if (wordIdx == 4095) begin
            Bit#(64) ghtBytes = zeroExtend((ghtCount + 3) / 4) * 64;
            readReqQ.enq(tuple2(baseAddr + 64 + 256*1024, ghtBytes));
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
            RuleInfo info = unpackRuleInfo(curWord[127:0]);
            Bit#(32) gram32 = curWord[31:0];
            gram.insert(gram32, info);
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
                done  <= True;
                state <= DLDone;
            end else begin
                state <= DLPortSmallFetch;
            end
        end else begin
            portSubIdx <= portSubIdx + 1;
        end
    endrule

    method Action startLoad(Bit#(64) dbBase, Bit#(32) dbBytes) if (state == DLIdle);
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
