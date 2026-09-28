package PacketStreamReader;

// AXI4-Stream packet input — DECOUPLED streaming (no whole-packet buffering).
import Vector::*;

import PacketMeta::*;
import PacketReader::*; 
import AxiStream::*;

function PktMetaFields unpackTuser(Bit#(128) u);
    return PktMetaFields {
        srcIp:    u[31:0],
        dstIp:    u[63:32],
        ipProto:  u[71:64],
        srcPort:  u[87:72],
        dstPort:  u[103:88],
        icmpType: u[111:104],
        icmpCode: u[119:112]
    };
endfunction

typedef struct {
    Bit#(32)      pktIdx;
    Bit#(512)     word;
    Bit#(7)       validBytes;
    Bool          first;
    Bool          last;
    Bit#(32)      payloadLen;
    PktMetaFields meta;
} StreamBeat deriving (Bits, Eq);

interface PacketStreamReaderIfc;
    method Action      enable;
    method Bool        beatAvailable;
    method StreamBeat  beat;
    method Action      advanceBeat;
    method Bool        busy;
    method Bool        pktReady;
    method Bool        pktDone;
    method Bool        feedAwaitingLine;
    method Bool        allDone;
    method Bool        descBusy;
    method Bool        startBusy;
    method Bool        startAwaitingPayload;
    method Bool        payloadRespBusy;
endinterface

module mkPacketStreamReader#(AxiStreamSlaveUserIfc#(512, 128) axisIn)
                            (PacketStreamReaderIfc);

    FIFOF#(StreamBeat) beatFifo <- mkSizedFIFOF(16);

    Reg#(Bool)     started  <- mkReg(False);
    Reg#(Bit#(32)) inPktIdx <- mkReg(0);    
    Reg#(Bit#(32)) inRunLen <- mkReg(0);   
    Reg#(Bool)     inFirst  <- mkReg(True); 

    rule ingest(started);
        let b <- axisIn.get;
        Bit#(7)  vbytes = b.last ? truncate(pack(countOnes(b.keep))) : 7'd64;
        Bit#(32) runLen = inRunLen + zeroExtend(vbytes);
        beatFifo.enq(StreamBeat {
            pktIdx: inPktIdx, word: b.data, validBytes: vbytes,
            first: inFirst, last: b.last,
            payloadLen: runLen, meta: unpackTuser(b.user) });
        if (b.last) begin
            inPktIdx <= inPktIdx + 1;
            inFirst  <= True;
            inRunLen <= 0;
        end else begin
            inFirst  <= False;
            inRunLen <= runLen;
        end
    endrule

    method Action enable;       started <= True;          endmethod
    method Bool       beatAvailable = beatFifo.notEmpty;
    method StreamBeat beat        = beatFifo.first;
    method Action     advanceBeat;  beatFifo.deq;         endmethod
    method Bool       busy        = started;

    method Bool pktReady             = beatFifo.notEmpty;
    method Bool pktDone              = False;
    method Bool feedAwaitingLine     = started && !beatFifo.notEmpty;
    method Bool allDone              = False;
    method Bool descBusy             = False;
    method Bool startBusy            = False;
    method Bool startAwaitingPayload = False;
    method Bool payloadRespBusy      = False;
endmodule

endpackage
