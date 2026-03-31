import FIFO::*;
import FIFOF::*;
import BRAM::*;
import Vector::*;

import BitmapLookup::*;
import CycleCounter::*;
import ExactMatch::*;
import HashTable::*;
import PacketParser::*;
import StaticDbMeta::*;

typedef 2 MemPortCnt;

typedef struct {
    Bit#(64) addr;
    Bit#(32) bytes;
} MemPortReq deriving (Eq, Bits);

interface MemPortIfc;
    method ActionValue#(MemPortReq) readReq;
    method ActionValue#(MemPortReq) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
    method Action readWord(Bit#(512) word);
endinterface

interface KernelMainIfc;
    method Action start(Bit#(32) param);
    method ActionValue#(Bool) done;
    interface Vector#(MemPortCnt, MemPortIfc) mem;
endinterface

typedef enum {
    KIdle,
    KReadHeaderReq,
    KReadHeaderResp,
    KDescReq,
    KDescResp,
    KDescParse,
    KPktReq,
    KPktResp,
    KPktFeed,
    KPktDrain,
    KDrain,
    KWriteReq,
    KWriteData,
    KDone
} KPhase deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) byteIdx;
    Bit#(3) bitIdx;
    Bit#(32) gram;
    Bit#(32) anchor;
} BitmapReq deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) gram;
    Bit#(32) anchor;
} GramHit deriving (Bits, Eq, FShow);

typedef enum {
    M1None,
    M1CkT0,
    M1CkT1,
    M1Cand
} Mem1Kind deriving (Bits, Eq, FShow);

typedef enum {
    CkIdle,
    CkNeedT0,
    CkNeedT1,
    CkNeedCount
} CkState deriving (Bits, Eq, FShow);

function Bit#(32) getWordU32(Bit#(512) w, Bit#(4) idx);
    Bit#(9) sh = zeroExtend(idx) << 5;
    return truncate(w >> sh);
endfunction

function Bit#(8) getWordU8(Bit#(512) w, Bit#(6) idx);
    Bit#(9) sh = zeroExtend(idx) << 3;
    return truncate(w >> sh);
endfunction

function Bit#(32) getLineU32(Bit#(512) w, Bit#(6) byteOff);
    Bit#(9) sh = zeroExtend(byteOff) << 3;
    return truncate(w >> sh);
endfunction

module mkKernelMain(KernelMainIfc);
    FIFO#(Bit#(32)) startQ <- mkFIFO;
    FIFO#(Bool) doneQ <- mkFIFO;

    Reg#(Bool) started <- mkReg(False);
    Reg#(Bit#(32)) paramReg <- mkReg(0);
    Reg#(KPhase) phase <- mkReg(KIdle);

    Vector#(MemPortCnt, FIFO#(MemPortReq)) readReqQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(MemPortReq)) writeReqQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512))) writeWordQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512))) readWordQs <- replicateM(mkFIFO);

    BitmapLookupIfc bitmapLookup <- mkBitmapLookup;

    BRAM_Configure gramdbCfg = defaultValue;
    gramdbCfg.memorySize = 65536;
    gramdbCfg.loadFormat = tagged Hex "generated/gramdb_512.hex";
    BRAM2Port#(Bit#(16), Bit#(512)) gramdbBram <- mkBRAM2Server(gramdbCfg);

    FIFOF#(BitmapReq) bitmapReqQ <- mkSizedFIFOF(1024);
    FIFOF#(GramHit) cuckooReqQ <- mkSizedFIFOF(1024);
    HashTableIfc hashTable <- mkHashTable;
    ExactMatchIfc exactMatch <- mkExactMatch;

    PacketParserIfc parser <- mkPacketParser;
    CycleCounterIfc cycleCounter <- mkCycleCounter;

    Reg#(Bit#(32)) hdrMagic <- mkReg(0);
    Reg#(Bit#(32)) hdrVersion <- mkReg(0);
    Reg#(Bit#(32)) hdrPktCount <- mkReg(0);
    Reg#(Bit#(32)) hdrPktDescBytes <- mkReg(0);
    Reg#(Bit#(32)) hdrPktBlobBytes <- mkReg(0);
    Reg#(Bit#(32)) hdrBitmapBytes <- mkReg(0);
    Reg#(Bit#(32)) hdrGramdbBytes <- mkReg(0);
    Reg#(Bit#(32)) hdrOffPktDesc <- mkReg(0);
    Reg#(Bit#(32)) hdrOffPktBlob <- mkReg(0);

    Reg#(Bit#(32)) gramdbAssignCount <- mkReg(0);
    Reg#(Bit#(32)) gramdbHtCapacity <- mkReg(0);
    Reg#(Bit#(32)) gramdbTable0Off <- mkReg(0);
    Reg#(Bit#(32)) gramdbTable1Off <- mkReg(0);
    Reg#(Bit#(32)) bitmapLineCount <- mkReg(0);
    Reg#(Bit#(32)) gramdbLineCount <- mkReg(0);

    Reg#(Bit#(32)) pktIdx <- mkReg(0);
    Reg#(Bool) descWordValid <- mkReg(False);
    Reg#(Bit#(64)) descWordAddr <- mkReg(0);
    Reg#(Bit#(512)) descWord <- mkReg(0);

    Reg#(Bit#(32)) curBlobOff <- mkReg(0);
    Reg#(Bit#(32)) curRawLen <- mkReg(0);

    Reg#(Bit#(32)) pktBytesRemaining <- mkReg(0);
    Reg#(Bit#(64)) feedAddr <- mkReg(0);
    Reg#(Bit#(7)) feedByteIdx <- mkReg(0);
    Reg#(Bit#(7)) feedWordLimit <- mkReg(0);
    Reg#(Bit#(512)) feedWord <- mkReg(0);

    Reg#(Bit#(32)) rawBytesFed <- mkReg(0);
    Reg#(Bit#(32)) payloadBytesSeen <- mkReg(0);
    Reg#(Bit#(32)) payloadPktEnds <- mkReg(0);
    Reg#(Bit#(32)) payloadPos <- mkReg(0);
    Reg#(Bit#(32)) payloadHash <- mkReg(32'h811C9DC5);
    Reg#(Bit#(8)) gramSr0 <- mkReg(0);
    Reg#(Bit#(8)) gramSr1 <- mkReg(0);
    Reg#(Bit#(2)) gramFill <- mkReg(0);
    Reg#(Bit#(32)) totalGrams <- mkReg(0);
    Reg#(Bit#(32)) bitmapHitGrams <- mkReg(0);
    Reg#(Bit#(32)) bitmapReqs <- mkReg(0);
    Reg#(Bit#(32)) cuckooLookups <- mkReg(0);
    Reg#(Bit#(32)) cuckooHits <- mkReg(0);
    Reg#(Bit#(32)) hashSeeds <- mkReg(0);
    Reg#(Bit#(32)) verifyReqs <- mkReg(0);
    Reg#(Bit#(32)) verifyHits <- mkReg(0);
    Reg#(Bit#(32)) pktPayloadBase <- mkReg(0);

    Reg#(Bool) mem1Pending <- mkReg(False);
    Reg#(Mem1Kind) mem1Kind <- mkReg(M1None);
    Reg#(Bit#(6)) mem1ByteInLine <- mkReg(0);
    Reg#(Bit#(32)) mem1Gram <- mkReg(0);

    Reg#(CkState) ckState <- mkReg(CkIdle);
    Reg#(Bit#(32)) ckGram <- mkReg(0);
    Reg#(Bit#(32)) ckAnchor <- mkReg(0);
    Reg#(Bit#(32)) ckH0 <- mkReg(0);
    Reg#(Bit#(32)) ckH1 <- mkReg(0);
    Reg#(Bit#(32)) ckBase <- mkReg(0);
    Reg#(Bit#(32)) ckCandIdx <- mkReg(0);
    Reg#(Bit#(32)) ckNCands <- mkReg(0);

    Reg#(Bit#(32)) errorFlags <- mkReg(0);

    rule systemStart(!started);
        startQ.deq;
        started <= True;
        paramReg <= startQ.first;
        phase <= KReadHeaderReq;
        cycleCounter.markStart;

        hdrMagic <= 0;
        hdrVersion <= 0;
        hdrPktCount <= 0;
        hdrPktDescBytes <= 0;
        hdrPktBlobBytes <= 0;
        hdrBitmapBytes <= 0;
        hdrGramdbBytes <= 0;
        hdrOffPktDesc <= 0;
        hdrOffPktBlob <= 0;
        gramdbAssignCount <= 0;
        gramdbHtCapacity <= 0;
        gramdbTable0Off <= 0;
        gramdbTable1Off <= 0;
        bitmapLineCount <= 0;
        gramdbLineCount <= 0;

        pktIdx <= 0;
        descWordValid <= False;
        descWordAddr <= 0;
        descWord <= 0;

        curBlobOff <= 0;
        curRawLen <= 0;
        pktBytesRemaining <= 0;
        feedAddr <= 0;
        feedByteIdx <= 0;
        feedWordLimit <= 0;
        feedWord <= 0;

        rawBytesFed <= 0;
        payloadBytesSeen <= 0;
        payloadPktEnds <= 0;
        payloadPos <= 0;
        payloadHash <= 32'h811C9DC5;
        gramSr0 <= 0;
        gramSr1 <= 0;
        gramFill <= 0;
        totalGrams <= 0;
        bitmapHitGrams <= 0;
        bitmapReqs <= 0;
        cuckooLookups <= 0;
        cuckooHits <= 0;
        hashSeeds <= 0;
        verifyReqs <= 0;
        verifyHits <= 0;
        pktPayloadBase <= 0;

        mem1Pending <= False;
        mem1Kind <= M1None;
        mem1ByteInLine <= 0;
        mem1Gram <= 0;

        ckState <= CkIdle;
        ckGram <= 0;
        ckAnchor <= 0;
        ckH0 <= 0;
        ckH1 <= 0;
        ckBase <= 0;
        ckCandIdx <= 0;
        ckNCands <= 0;

        errorFlags <= 0;
    endrule

    rule issueHeaderReq(started && phase == KReadHeaderReq);
        readReqQs[0].enq(MemPortReq { addr: 0, bytes: 64 });
        phase <= KReadHeaderResp;
    endrule

    rule recvHeader(started && phase == KReadHeaderResp);
        readWordQs[0].deq;
        let w = readWordQs[0].first;

        let magic = getWordU32(w, 4'd0);
        let version = getWordU32(w, 4'd1);
        let pktCount = getWordU32(w, 4'd2);
        let pktDescBytes = getWordU32(w, 4'd3);
        let pktBlobBytes = getWordU32(w, 4'd4);
        let bitmapBytesHost = getWordU32(w, 4'd5);
        let gramdbBytesHost = getWordU32(w, 4'd6);
        let offPktDesc = getWordU32(w, 4'd7);
        let offPktBlob = getWordU32(w, 4'd8);

        hdrMagic <= magic;
        hdrVersion <= version;
        hdrPktCount <= pktCount;
        hdrPktDescBytes <= pktDescBytes;
        hdrPktBlobBytes <= pktBlobBytes;
        hdrOffPktDesc <= offPktDesc;
        hdrOffPktBlob <= offPktBlob;

        Bit#(32) bitmapBytesEff = staticBitmapBytes;
        Bit#(32) gramdbBytesEff = staticGramdbBytes;
        Bit#(32) bmLines = staticBitmapLines;
        Bit#(32) gdLines = staticGramdbLines;
        Bit#(32) hdrErr = 0;

        hdrBitmapBytes <= bitmapBytesEff;
        hdrGramdbBytes <= gramdbBytesEff;

        if (magic != 32'h4D4B5931) begin
            hdrErr = hdrErr | 32'h00000001;
        end
        if (bmLines > 32'd32768) begin
            hdrErr = hdrErr | 32'h00000100;
        end
        if (gdLines > 32'd65536) begin
            hdrErr = hdrErr | 32'h00000200;
        end
        if (staticGramdbHtCapacity == 0) begin
            hdrErr = hdrErr | 32'h00000004;
        end
        if (bitmapBytesHost != staticBitmapBytes) begin
            hdrErr = hdrErr | 32'h00004000;
        end
        if (gramdbBytesHost != staticGramdbBytes) begin
            hdrErr = hdrErr | 32'h00008000;
        end

        bitmapLineCount <= bmLines;
        gramdbLineCount <= gdLines;
        gramdbAssignCount <= staticGramdbAssignCount;
        gramdbHtCapacity <= staticGramdbHtCapacity;
        gramdbTable0Off <= staticGramdbTable0Off;
        gramdbTable1Off <= staticGramdbTable1Off;

        if (hdrErr != 0) begin
            errorFlags <= errorFlags | hdrErr;
        end

        pktIdx <= 0;
        phase <= (pktCount == 0) ? KDrain : KDescReq;
    endrule

    rule issueDescReq(started && phase == KDescReq && pktIdx < hdrPktCount);
        Bit#(32) blockIdx = pktIdx >> 2;
        Bit#(64) addr = zeroExtend(hdrOffPktDesc) + (zeroExtend(blockIdx) << 6);
        if (!descWordValid || descWordAddr != addr) begin
            readReqQs[0].enq(MemPortReq { addr: addr, bytes: 64 });
            descWordAddr <= addr;
            phase <= KDescResp;
        end else begin
            phase <= KDescParse;
        end
    endrule

    rule recvDescWord(started && phase == KDescResp);
        readWordQs[0].deq;
        descWord <= readWordQs[0].first;
        descWordValid <= True;
        phase <= KDescParse;
    endrule

    rule parseDesc(started && phase == KDescParse);
        Bit#(4) slotBase = zeroExtend(pktIdx[1:0]) << 2;
        let blobOff = getWordU32(descWord, slotBase);
        let rawLen = getWordU32(descWord, slotBase + 4'd1);

        curBlobOff <= blobOff;
        curRawLen <= rawLen;

        if (rawLen == 0) begin
            pktIdx <= pktIdx + 1;
            phase <= (pktIdx + 1 >= hdrPktCount) ? KDrain : KDescReq;
        end else begin
            Bit#(64) absAddr = zeroExtend(hdrOffPktBlob) + zeroExtend(blobOff);
            feedAddr <= {absAddr[63:6], 6'b0};
            feedByteIdx <= zeroExtend(absAddr[5:0]);
            pktBytesRemaining <= rawLen;
            phase <= KPktReq;
        end
    endrule

    rule issuePktReq(started && phase == KPktReq);
        readReqQs[0].enq(MemPortReq { addr: feedAddr, bytes: 64 });
        phase <= KPktResp;
    endrule

    rule recvPktWord(started && phase == KPktResp);
        readWordQs[0].deq;
        let w = readWordQs[0].first;
        Bit#(7) startIdx = feedByteIdx;
        Bit#(7) avail = 7'd64 - startIdx;
        Bit#(32) avail32 = zeroExtend(avail);
        Bit#(32) send32 = (pktBytesRemaining < avail32) ? pktBytesRemaining : avail32;

        feedWord <= w;
        feedWordLimit <= startIdx + truncate(send32);
        phase <= KPktFeed;
    endrule

    rule feedPktByte(started && phase == KPktFeed && parser.canPut && feedByteIdx < feedWordLimit);
        Bit#(8) b = getWordU8(feedWord, truncate(feedByteIdx));
        Bool last = (pktBytesRemaining == 1);
        Bit#(7) nextIdx = feedByteIdx + 1;

        parser.putByte(b, last);

        rawBytesFed <= rawBytesFed + 1;
        pktBytesRemaining <= pktBytesRemaining - 1;

        if (nextIdx == feedWordLimit) begin
            if (pktBytesRemaining == 1) begin
                let nextPkt = pktIdx + 1;
                pktIdx <= nextPkt;
                feedByteIdx <= nextIdx;
                phase <= (nextPkt >= hdrPktCount) ? KDrain : KDescReq;
            end else begin
                feedAddr <= feedAddr + 64;
                feedByteIdx <= 0;
                phase <= KPktReq;
            end
        end else begin
            feedByteIdx <= nextIdx;
        end
    endrule

    rule drainPayload(started && parser.payloadNotEmpty && ((gramFill < 2) || bitmapReqQ.notFull));
        let t <- parser.getPayloadByte;
        let b = tpl_1(t);
        let lst = tpl_2(t);
        exactMatch.putPayloadByte(b, lst);
        let nextFill = (gramFill >= 3) ? 3 : gramFill + 1;
        let curPos = payloadPos;

        payloadBytesSeen <= payloadBytesSeen + 1;
        payloadHash <= ((payloadHash << 5) + payloadHash) ^ zeroExtend(b);

        if (nextFill >= 3) begin
            Bit#(24) gram = {gramSr0, gramSr1, b};
            Bit#(32) gram32 = zeroExtend(gram);
            Bit#(32) anchor = curPos - 2;
            bitmapReqQ.enq(BitmapReq {
                byteIdx: (gram32 >> 3),
                bitIdx: truncate(gram32),
                gram: gram32,
                anchor: anchor
            });
            totalGrams <= totalGrams + 1;
        end

        gramSr0 <= gramSr1;
        gramSr1 <= b;

        if (lst) begin
            gramFill <= 0;
            payloadPos <= 0;
            payloadPktEnds <= payloadPktEnds + 1;
        end else begin
            gramFill <= nextFill;
            payloadPos <= curPos + 1;
        end
    endrule

    rule issueBitmapReq(started && bitmapReqQ.notEmpty && bitmapLookup.reqReady);
        let req = bitmapReqQ.first;
        bitmapReqQ.deq;

        if (req.byteIdx < hdrBitmapBytes) begin
            Bit#(32) lineBase = {req.byteIdx[31:6], 6'b0};
            Bit#(32) lineIdx = lineBase >> 6;
            if (lineIdx < bitmapLineCount && lineIdx < 32'd32768) begin
                bitmapLookup.putReq(BitmapLookupReq {
                    byteIdx: req.byteIdx,
                    bitIdx: req.bitIdx,
                    gram: req.gram,
                    anchor: req.anchor
                });
                bitmapReqs <= bitmapReqs + 1;
            end else begin
                errorFlags <= errorFlags | 32'h00000400;
            end
        end else begin
            errorFlags <= errorFlags | 32'h00000002;
        end
    endrule

    rule loadCuckooReq(started && ckState == CkIdle && cuckooReqQ.notEmpty && gramdbHtCapacity != 0);
        let r = cuckooReqQ.first;
        cuckooReqQ.deq;

        ckGram <= r.gram;
        ckAnchor <= r.anchor;
        ckH0 <= r.gram % gramdbHtCapacity;
        ckH1 <= (r.gram * 32'h9E3779B1) % gramdbHtCapacity;
        ckState <= CkNeedT0;
        cuckooLookups <= cuckooLookups + 1;
    endrule

    rule issueCuckooT0(started && ckState == CkNeedT0 && !mem1Pending);
        Bit#(32) entryAddr = gramdbTable0Off + (ckH0 << 3);
        Bit#(32) lineIdx = entryAddr >> 6;
        if (lineIdx < gramdbLineCount && lineIdx < 32'd65536) begin
            gramdbBram.portA.request.put(BRAMRequest {
                write: False,
                responseOnWrite: False,
                address: truncate(lineIdx),
                datain: ?
            });
            mem1Pending <= True;
            mem1Kind <= M1CkT0;
            mem1ByteInLine <= entryAddr[5:0];
            mem1Gram <= ckGram;
        end else begin
            errorFlags <= errorFlags | 32'h00000800;
            ckState <= CkIdle;
        end
    endrule

    rule issueCuckooT1(started && ckState == CkNeedT1 && !mem1Pending);
        Bit#(32) entryAddr = gramdbTable1Off + (ckH1 << 3);
        Bit#(32) lineIdx = entryAddr >> 6;
        if (lineIdx < gramdbLineCount && lineIdx < 32'd65536) begin
            gramdbBram.portA.request.put(BRAMRequest {
                write: False,
                responseOnWrite: False,
                address: truncate(lineIdx),
                datain: ?
            });
            mem1Pending <= True;
            mem1Kind <= M1CkT1;
            mem1ByteInLine <= entryAddr[5:0];
            mem1Gram <= ckGram;
        end else begin
            errorFlags <= errorFlags | 32'h00000800;
            ckState <= CkIdle;
        end
    endrule

    rule issueCandRead(started && ckState == CkNeedCount && !mem1Pending);
        Bit#(32) idx = ckBase + ckCandIdx;
        if (idx < gramdbAssignCount) begin
            Bit#(32) recAddr = 32'd8 + idx * 32'd272;
            Bit#(32) lineIdx = recAddr >> 6;
            if (lineIdx < gramdbLineCount && lineIdx < 32'd65536) begin
                gramdbBram.portA.request.put(BRAMRequest {
                    write: False,
                    responseOnWrite: False,
                    address: truncate(lineIdx),
                    datain: ?
                });
                mem1Pending <= True;
                mem1Kind <= M1Cand;
                mem1ByteInLine <= recAddr[5:0];
                mem1Gram <= ckGram;
            end else begin
                errorFlags <= errorFlags | 32'h00001000;
                ckState <= CkIdle;
            end
        end else begin
            if (ckNCands != 0) begin
                if (hashTable.seedReady) begin
                    hashTable.putSeed(HashSeed { anchor: ckAnchor, base: ckBase, nCands: ckNCands });
                    hashSeeds <= hashSeeds + 1;
                end else begin
                    errorFlags <= errorFlags | 32'h00000020;
                end
            end
            ckState <= CkIdle;
        end
    endrule

    rule recvBitmapRsp(started && bitmapLookup.rspValid);
        let r <- bitmapLookup.getRsp;
        if (r.hit) begin
            bitmapHitGrams <= bitmapHitGrams + 1;
            if (gramdbHtCapacity != 0) begin
                if (cuckooReqQ.notFull) begin
                    cuckooReqQ.enq(GramHit { gram: r.gram, anchor: r.anchor });
                end else begin
                    errorFlags <= errorFlags | 32'h00000008;
                end
            end else begin
                errorFlags <= errorFlags | 32'h00000004;
            end
        end
    endrule

    rule recvMem1Gramdb(started && mem1Pending && mem1Kind != M1None);
        let w <- gramdbBram.portA.response.get();

        case (mem1Kind)
            M1CkT0: begin
                Bit#(32) key = getLineU32(w, mem1ByteInLine);
                Bit#(32) val = getLineU32(w, mem1ByteInLine + 4);
                if (key == mem1Gram && val[31] == 0) begin
                    ckBase <= val;
                    ckCandIdx <= 0;
                    ckNCands <= 0;
                    ckState <= CkNeedCount;
                    cuckooHits <= cuckooHits + 1;
                end else begin
                    ckState <= CkNeedT1;
                end
            end

            M1CkT1: begin
                Bit#(32) key = getLineU32(w, mem1ByteInLine);
                Bit#(32) val = getLineU32(w, mem1ByteInLine + 4);
                if (key == mem1Gram && val[31] == 0) begin
                    ckBase <= val;
                    ckCandIdx <= 0;
                    ckNCands <= 0;
                    ckState <= CkNeedCount;
                    cuckooHits <= cuckooHits + 1;
                end else begin
                    ckState <= CkIdle;
                end
            end

            M1Cand: begin
                Bit#(32) gramIdx = getLineU32(w, mem1ByteInLine);
                if (gramIdx == mem1Gram) begin
                    ckNCands <= ckNCands + 1;
                    ckCandIdx <= ckCandIdx + 1;
                    ckState <= CkNeedCount;
                end else begin
                    if (ckNCands != 0) begin
                        if (hashTable.seedReady) begin
                            hashTable.putSeed(HashSeed { anchor: ckAnchor, base: ckBase, nCands: ckNCands });
                            hashSeeds <= hashSeeds + 1;
                        end else begin
                            errorFlags <= errorFlags | 32'h00000020;
                        end
                    end
                    ckState <= CkIdle;
                end
            end

            default: begin
            end
        endcase

        mem1Pending <= False;
        mem1Kind <= M1None;
    endrule

    rule emitVerifyReq(started && hashTable.reqValid);
        let _req <- hashTable.getRequest;
        verifyReqs <= verifyReqs + 1;
    endrule

    rule waitDrain(started && phase == KDrain);
        if (!parser.payloadNotEmpty
            && !bitmapReqQ.notEmpty
            && !bitmapLookup.busy
            && !cuckooReqQ.notEmpty
            && !hashTable.busy
            && !mem1Pending
            && ckState == CkIdle) begin
            phase <= KWriteReq;
        end
    endrule

    rule issueWriteReq(started && phase == KWriteReq);
        writeReqQs[1].enq(MemPortReq { addr: 0, bytes: 64 });
        phase <= KWriteData;
    endrule

    rule issueWriteData(started && phase == KWriteData);
        cycleCounter.markDone;
        let cycStart = cycleCounter.getStart;
        let cycDone = cycleCounter.value;

        Bit#(512) out = 0;
        out[31:0] = hdrPktCount;
        out[63:32] = cuckooHits;
        out[95:64] = totalGrams;
        out[127:96] = bitmapHitGrams;
        out[159:128] = cuckooLookups;
        out[191:160] = verifyReqs;
        out[223:192] = payloadBytesSeen;
        out[255:224] = rawBytesFed;
        out[287:256] = payloadHash;
        out[319:288] = payloadPktEnds;
        out[351:320] = errorFlags;
        out[383:352] = hdrVersion;
        out[415:384] = cycStart;
        out[447:416] = cycDone;
        out[479:448] = cycDone - cycStart;
        out[511:480] = hdrMagic;

        writeWordQs[1].enq(out);
        phase <= KDone;
    endrule

    rule finish(started && phase == KDone);
        doneQ.enq(True);
        started <= False;
        phase <= KIdle;
    endrule

    Vector#(MemPortCnt, MemPortIfc) mem_;
    for (Integer i = 0; i < valueOf(MemPortCnt); i = i + 1) begin
        mem_[i] = interface MemPortIfc;
            method ActionValue#(MemPortReq) readReq;
                readReqQs[i].deq;
                return readReqQs[i].first;
            endmethod

            method ActionValue#(MemPortReq) writeReq;
                writeReqQs[i].deq;
                return writeReqQs[i].first;
            endmethod

            method ActionValue#(Bit#(512)) writeWord;
                writeWordQs[i].deq;
                return writeWordQs[i].first;
            endmethod

            method Action readWord(Bit#(512) word);
                readWordQs[i].enq(word);
            endmethod
        endinterface;
    end

    method Action start(Bit#(32) param) if (!started);
        startQ.enq(param);
    endmethod

    method ActionValue#(Bool) done;
        doneQ.deq;
        return doneQ.first;
    endmethod

    interface mem = mem_;
endmodule
