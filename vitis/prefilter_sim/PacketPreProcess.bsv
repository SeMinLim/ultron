package PacketPreProcess;

import FIFO::*;
import FIFOF::*;
import BRAM::*;

import PacketParserTypes::*;

typedef struct {
  Bit#(16) port;
  Bit#(16) mappedPort;
} PortMapWriteReq deriving (Bits, Eq);

interface PacketPreProcessIfc;
  method Action enq(PacketMeta meta);
  method Bool valid;
  method PacketMeta first;
  method Action deq;
  method Action writeMap(Bit#(16) port, Bit#(16) mappedPort);
endinterface

module mkPacketPreProcess(PacketPreProcessIfc);
  FIFOF#(PacketMeta) inQ <- mkFIFOF;
  FIFOF#(PacketMeta) outQ <- mkFIFOF;
  FIFO#(PortMapWriteReq) writeQ <- mkFIFO;

  BRAM2Port#(Bit#(16), Bit#(16)) portMap <- mkBRAM2Server(defaultValue);

  Reg#(Bool) busy <- mkReg(False);
  Reg#(PacketMeta) pending <- mkRegU;
  Reg#(Bool) pendingTcpUdp <- mkReg(False);

  rule doWrite(!busy && writeQ.notEmpty);
    let w = writeQ.first;
    writeQ.deq;
    portMap.portA.request.put(BRAMRequest{write: True, responseOnWrite: False, address: w.port, datain: w.mappedPort});
  endrule

  rule startMap(!busy && writeQ.isEmpty && inQ.notEmpty);
    let m = inQ.first;
    if (m.protocol == 6 || m.protocol == 17) begin
      inQ.deq;
      pending <= m;
      pendingTcpUdp <= True;
      busy <= True;
      portMap.portA.request.put(BRAMRequest{write: False, responseOnWrite: False, address: m.srcPort, datain: ?});
      portMap.portB.request.put(BRAMRequest{write: False, responseOnWrite: False, address: m.dstPort, datain: ?});
    end else if (outQ.notFull) begin
      inQ.deq;
      outQ.enq(m);
    end
  endrule

  rule finishMap(busy && pendingTcpUdp && outQ.notFull);
    let mappedSrc <- portMap.portA.response.get();
    let mappedDst <- portMap.portB.response.get();
    PacketMeta m = pending;
    m.srcPort = mappedSrc;
    m.dstPort = mappedDst;
    outQ.enq(m);
    busy <= False;
  endrule

  method Action enq(PacketMeta meta);
    inQ.enq(meta);
  endmethod

  method Bool valid;
    return outQ.notEmpty;
  endmethod
  method PacketMeta first;
    return outQ.first;
  endmethod
  method Action deq;
    outQ.deq;
  endmethod

  method Action writeMap(Bit#(16) port, Bit#(16) mappedPort);
    writeQ.enq(PortMapWriteReq{port: port, mappedPort: mappedPort});
  endmethod
endmodule

endpackage: PacketPreProcess
