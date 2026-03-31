import FIFO::*;
import FIFOF::*;
import BRAM::*;

typedef struct {
    Bit#(32) byteIdx;
    Bit#(3) bitIdx;
    Bit#(32) gram;
    Bit#(32) anchor;
} BitmapLookupReq deriving (Bits, Eq, FShow);

typedef struct {
    Bool hit;
    Bit#(32) gram;
    Bit#(32) anchor;
} BitmapLookupRsp deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(6) byteInLine;
    Bit#(3) bitIdx;
    Bit#(32) gram;
    Bit#(32) anchor;
} BitmapLookupMeta deriving (Bits, Eq, FShow);

interface BitmapLookupIfc;
    method Action putReq(BitmapLookupReq req);
    method ActionValue#(BitmapLookupRsp) getRsp;

    method Bool reqReady;
    method Bool rspValid;
    method Bool busy;
endinterface

function Bit#(8) getWordU8(Bit#(512) w, Bit#(6) idx);
    Bit#(9) sh = zeroExtend(idx) << 3;
    return truncate(w >> sh);
endfunction

module mkBitmapLookup(BitmapLookupIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize = 32768;
    cfg.loadFormat = tagged Hex "generated/bitmap_512.hex";
    BRAM2Port#(Bit#(15), Bit#(512)) bram <- mkBRAM2Server(cfg);

    FIFOF#(BitmapLookupMeta) pendingQ <- mkSizedFIFOF(1024);
    FIFOF#(BitmapLookupRsp) outQ <- mkSizedFIFOF(1024);

    rule checkHit(pendingQ.notEmpty);
        let m = pendingQ.first;
        pendingQ.deq;

        let line <- bram.portA.response.get();
        Bit#(8) mapByte = getWordU8(line, m.byteInLine);
        Bool hit = (((mapByte >> m.bitIdx) & 8'h01) != 0);

        outQ.enq(BitmapLookupRsp {
            hit: hit,
            gram: m.gram,
            anchor: m.anchor
        });
    endrule

    method Action putReq(BitmapLookupReq req) if (pendingQ.notFull);
        Bit#(32) lineIdx = req.byteIdx >> 6;
        bram.portA.request.put(BRAMRequest {
            write: False,
            responseOnWrite: False,
            address: truncate(lineIdx),
            datain: ?
        });
        pendingQ.enq(BitmapLookupMeta {
            byteInLine: req.byteIdx[5:0],
            bitIdx: req.bitIdx,
            gram: req.gram,
            anchor: req.anchor
        });
    endmethod

    method ActionValue#(BitmapLookupRsp) getRsp if (outQ.notEmpty);
        let r = outQ.first;
        outQ.deq;
        return r;
    endmethod

    method Bool reqReady = pendingQ.notFull;
    method Bool rspValid = outQ.notEmpty;
    method Bool busy = pendingQ.notEmpty || outQ.notEmpty;
endmodule
