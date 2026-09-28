package AxiStream;

import FIFOF::*;

interface AxiStreamMasterPinsIfc#(numeric type dataSz);
    (* always_ready, result="tvalid" *)
    method Bool tvalid;
    (* always_ready, always_enabled, prefix="" *)
    method Action tready ((* port="tready" *) Bool r);
    (* always_ready, result="tdata" *)
    method Bit#(dataSz) tdata;
    (* always_ready, result="tkeep" *)
    method Bit#(TDiv#(dataSz,8)) tkeep;
    (* always_ready, result="tlast" *)
    method Bool tlast;
endinterface

interface AxiStreamMasterIfc#(numeric type dataSz);
    interface AxiStreamMasterPinsIfc#(dataSz) pins;
    method Action put(Bit#(dataSz) data, Bit#(TDiv#(dataSz,8)) keep, Bool last);
endinterface

(* synthesize *)
module mkAxiStreamMaster_512 (AxiStreamMasterIfc#(512));
    let m_ <- mkAxiStreamMaster;
    return m_;
endmodule

(* synthesize *)
module mkAxiStreamMaster_32 (AxiStreamMasterIfc#(32));
    let m_ <- mkAxiStreamMaster;
    return m_;
endmodule

module mkAxiStreamMaster (AxiStreamMasterIfc#(dataSz));
    FIFOF#(Tuple3#(Bit#(dataSz), Bit#(TDiv#(dataSz,8)), Bool)) outQ <- mkFIFOF;

    RWire#(Tuple3#(Bit#(dataSz), Bit#(TDiv#(dataSz,8)), Bool)) beatW <- mkRWire;
    PulseWire readyW <- mkPulseWire;

    rule present(outQ.notEmpty);
        beatW.wset(outQ.first);
    endrule

    rule consume(readyW && outQ.notEmpty);
        outQ.deq;
    endrule

    interface AxiStreamMasterPinsIfc pins;
        method Bool tvalid;
            return isValid(beatW.wget);
        endmethod
        method Action tready (Bool r);
            if (r) readyW.send;
        endmethod
        method Bit#(dataSz) tdata;
            return tpl_1(fromMaybe(?, beatW.wget));
        endmethod
        method Bit#(TDiv#(dataSz,8)) tkeep;
            return tpl_2(fromMaybe(?, beatW.wget));
        endmethod
        method Bool tlast;
            return tpl_3(fromMaybe(?, beatW.wget));
        endmethod
    endinterface

    method Action put(Bit#(dataSz) data, Bit#(TDiv#(dataSz,8)) keep, Bool last);
        outQ.enq(tuple3(data, keep, last));
    endmethod
endmodule

interface AxiStreamSlavePinsIfc#(numeric type dataSz);
    (* always_ready, always_enabled, prefix="" *)
    method Action tvalid ((* port="tvalid" *) Bool v);
    (* always_ready, result="tready" *)
    method Bool tready;
    (* always_ready, always_enabled, prefix="" *)
    method Action tdata ((* port="tdata" *) Bit#(dataSz) d);
    (* always_ready, always_enabled, prefix="" *)
    method Action tkeep ((* port="tkeep" *) Bit#(TDiv#(dataSz,8)) k);
    (* always_ready, always_enabled, prefix="" *)
    method Action tlast ((* port="tlast" *) Bool l);
endinterface

interface AxiStreamSlaveIfc#(numeric type dataSz);
    interface AxiStreamSlavePinsIfc#(dataSz) pins;
    method ActionValue#(Tuple3#(Bit#(dataSz), Bit#(TDiv#(dataSz,8)), Bool)) get;
endinterface

(* synthesize *)
module mkAxiStreamSlave_512 (AxiStreamSlaveIfc#(512));
    let m_ <- mkAxiStreamSlave;
    return m_;
endmodule

module mkAxiStreamSlave (AxiStreamSlaveIfc#(dataSz));
    FIFOF#(Tuple3#(Bit#(dataSz), Bit#(TDiv#(dataSz,8)), Bool)) inQ <- mkFIFOF;

    PulseWire                    validW <- mkPulseWire;
    RWire#(Bit#(dataSz))         dataW  <- mkRWire;
    RWire#(Bit#(TDiv#(dataSz,8))) keepW <- mkRWire;
    RWire#(Bool)                 lastW  <- mkRWire;

    rule capture(inQ.notFull && validW);
        inQ.enq(tuple3(fromMaybe(?, dataW.wget),
                       fromMaybe(?, keepW.wget),
                       fromMaybe(False, lastW.wget)));
    endrule

    interface AxiStreamSlavePinsIfc pins;
        method Action tvalid (Bool v);
            if (v) validW.send;
        endmethod
        method Bool tready;
            return inQ.notFull;
        endmethod
        method Action tdata (Bit#(dataSz) d);
            dataW.wset(d);
        endmethod
        method Action tkeep (Bit#(TDiv#(dataSz,8)) k);
            keepW.wset(k);
        endmethod
        method Action tlast (Bool l);
            lastW.wset(l);
        endmethod
    endinterface

    method ActionValue#(Tuple3#(Bit#(dataSz), Bit#(TDiv#(dataSz,8)), Bool)) get;
        inQ.deq;
        return inQ.first;
    endmethod
endmodule

// AXI4-Stream slave with TUSER sideband (valid on the TLAST beat, per the
// Nixion interface diagram: tdata streams, tuser/tkeep carry final-beat metadata).
typedef struct {
    Bit#(dataSz)        data;
    Bit#(TDiv#(dataSz,8)) keep;
    Bit#(userSz)        user;
    Bool                last;
} AxiStreamBeatUser#(numeric type dataSz, numeric type userSz) deriving (Bits, Eq, FShow);

interface AxiStreamSlaveUserPinsIfc#(numeric type dataSz, numeric type userSz);
    (* always_ready, always_enabled, prefix="" *)
    method Action tvalid ((* port="tvalid" *) Bool v);
    (* always_ready, result="tready" *)
    method Bool tready;
    (* always_ready, always_enabled, prefix="" *)
    method Action tdata ((* port="tdata" *) Bit#(dataSz) d);
    (* always_ready, always_enabled, prefix="" *)
    method Action tkeep ((* port="tkeep" *) Bit#(TDiv#(dataSz,8)) k);
    (* always_ready, always_enabled, prefix="" *)
    method Action tuser ((* port="tuser" *) Bit#(userSz) u);
    (* always_ready, always_enabled, prefix="" *)
    method Action tlast ((* port="tlast" *) Bool l);
endinterface

interface AxiStreamSlaveUserIfc#(numeric type dataSz, numeric type userSz);
    interface AxiStreamSlaveUserPinsIfc#(dataSz, userSz) pins;
    method ActionValue#(AxiStreamBeatUser#(dataSz, userSz)) get;
endinterface

(* synthesize *)
module mkAxiStreamSlaveUser_512_128 (AxiStreamSlaveUserIfc#(512, 128));
    let m_ <- mkAxiStreamSlaveUser;
    return m_;
endmodule

module mkAxiStreamSlaveUser (AxiStreamSlaveUserIfc#(dataSz, userSz));
    FIFOF#(AxiStreamBeatUser#(dataSz, userSz)) inQ <- mkFIFOF;

    PulseWire                     validW <- mkPulseWire;
    RWire#(Bit#(dataSz))          dataW  <- mkRWire;
    RWire#(Bit#(TDiv#(dataSz,8))) keepW  <- mkRWire;
    RWire#(Bit#(userSz))          userW  <- mkRWire;
    RWire#(Bool)                  lastW  <- mkRWire;

    rule capture(inQ.notFull && validW);
        inQ.enq(AxiStreamBeatUser {
            data: fromMaybe(?, dataW.wget),
            keep: fromMaybe(?, keepW.wget),
            user: fromMaybe(?, userW.wget),
            last: fromMaybe(False, lastW.wget)
        });
    endrule

    interface AxiStreamSlaveUserPinsIfc pins;
        method Action tvalid (Bool v);
            if (v) validW.send;
        endmethod
        method Bool tready;
            return inQ.notFull;
        endmethod
        method Action tdata (Bit#(dataSz) d);
            dataW.wset(d);
        endmethod
        method Action tkeep (Bit#(TDiv#(dataSz,8)) k);
            keepW.wset(k);
        endmethod
        method Action tuser (Bit#(userSz) u);
            userW.wset(u);
        endmethod
        method Action tlast (Bool l);
            lastW.wset(l);
        endmethod
    endinterface

    method ActionValue#(AxiStreamBeatUser#(dataSz, userSz)) get;
        inQ.deq;
        return inQ.first;
    endmethod
endmodule

endpackage
