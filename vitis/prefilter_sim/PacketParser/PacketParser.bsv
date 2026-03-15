package PacketParser;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import PcieCtrl::*;
import PacketParserTypes::*;
import ParseUDP::*;
import ParseTCP::*;
import ParseICMP::*;

module mkPacketParser(PacketParserIfc);
  FIFOF#(DMAWord) inQ <- mkFIFOF;
  FIFOF#(DMAWord) outQ <- mkFIFOF;
  FIFOF#(PacketMeta) metaQ <- mkFIFOF;

  Reg#(Bit#(2)) state <- mkReg(0);
  Vector#(4, Reg#(DMAWord)) parseBuf <- replicateM(mkRegU);
  Reg#(Bit#(3)) bufCount <- mkReg(0);
  Reg#(Bit#(16)) wordsToOutput <- mkReg(0);
  Reg#(Bit#(16)) wordsOutput <- mkReg(0);
  Reg#(Bit#(3)) bufOutIdx <- mkReg(0);

  rule bufferWords(state == 0 && bufCount < 4);
    inQ.deq;
    parseBuf[bufCount] <= inQ.first;
    if (bufCount == 3) begin
      state <= 1;
      bufCount <= 0;
    end else begin
      bufCount <= bufCount + 1;
    end
  endrule

  rule parseHeaders(state == 1);
    let w0 = parseBuf[0];
    let w1 = parseBuf[1];
    let w2 = parseBuf[2];

    Bit#(8) versionIhl = getByte128(w0, 14);
    Bit#(4) ihl = versionIhl[3:0];
    Bit#(32) ipHeaderLenBytes = zeroExtend(ihl) << 2;

    Bit#(16) totalLength = getWord16BE(w1, 0);
    Bit#(8) protocol = getByte128(w1, 7);
    Bit#(32) srcIp = getWord32BE(w1, 10);
    Bit#(32) dstIp = {getWord16BE(w1, 14), getWord16BE(w2, 0)};

    Bit#(32) l4Start = 14 + ipHeaderLenBytes;
    L4ParseResult l4;

    if (protocol == 17)
      l4 = parseUDP(w2);
    else if (protocol == 6)
      l4 = parseTCP(w2);
    else if (protocol == 1)
      l4 = parseICMP(w2);
    else
      l4 = L4ParseResult{ srcPort: 0, dstPort: 0, l4HeaderLen: 0 };

    Bit#(32) payloadStart = l4Start + l4.l4HeaderLen;
    Bit#(32) payloadLength = (zeroExtend(totalLength) - ipHeaderLenBytes) - l4.l4HeaderLen;
    Bit#(16) payloadStart16 = truncate(payloadStart);
    Bit#(16) payloadLength16 = truncate(payloadLength);

    PacketMeta meta = PacketMeta{
      protocol: protocol,
      srcPort: l4.srcPort,
      dstPort: l4.dstPort,
      srcIp: srcIp,
      dstIp: dstIp,
      totalLength: totalLength,
      payloadOffset: payloadStart16,
      payloadLength: payloadLength16
    };

    metaQ.enq(meta);

    Bit#(32) frameLength = 14 + zeroExtend(totalLength);
    Bit#(32) totalWords32 = (frameLength + 15) >> 4;
    wordsToOutput <= truncate(totalWords32);
    wordsOutput <= 0;
    bufOutIdx <= 0;
    state <= 2;
  endrule

  rule outputBufferedWords(state == 2 && bufOutIdx < 4);
    outQ.enq(parseBuf[bufOutIdx]);
    bufOutIdx <= bufOutIdx + 1;
    let nextOut = wordsOutput + 1;
    wordsOutput <= nextOut;
    if (nextOut >= wordsToOutput) begin
      state <= 0;
      if (wordsToOutput == 1) begin
        parseBuf[0] <= parseBuf[1];
        parseBuf[1] <= parseBuf[2];
        parseBuf[2] <= parseBuf[3];
        bufCount <= 3;
      end else if (wordsToOutput == 2) begin
        parseBuf[0] <= parseBuf[2];
        parseBuf[1] <= parseBuf[3];
        bufCount <= 2;
      end else if (wordsToOutput == 3) begin
        parseBuf[0] <= parseBuf[3];
        bufCount <= 1;
      end else begin
        bufCount <= 0;
      end
    end
  endrule

  rule outputRemainingWords(state == 2 && bufOutIdx == 4 && wordsOutput < wordsToOutput);
    inQ.deq;
    outQ.enq(inQ.first);
    let nextOut = wordsOutput + 1;
    wordsOutput <= nextOut;
    if (nextOut >= wordsToOutput) begin
      state <= 0;
    end
  endrule

  method Action enq(DMAWord data);
    inQ.enq(data);
  endmethod

  method Bool payloadValid;
    return outQ.notEmpty;
  endmethod
  method DMAWord payloadFirst;
    return outQ.first;
  endmethod
  method Action payloadDeq;
    outQ.deq;
  endmethod

  method Bool metaValid;
    return metaQ.notEmpty;
  endmethod
  method PacketMeta metaFirst;
    return metaQ.first;
  endmethod
  method Action metaDeq;
    metaQ.deq;
  endmethod
endmodule

function DMAWord getTestWord(Bit#(3) i);
  case (i)
    0: return 128'h0000_0000_0000_0000_0000_0000_0800_4500;
    1: return 128'h0032_0000_0000_4011_0000_c0a8_0101_c0a8;
    2: return 128'h0102_3039_D431_0008_0000_0000_0000_0000;
    3: return 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    default: return 128'h0;
  endcase
endfunction

function DMAWord getTestWordIcmp(Bit#(3) i);
  case (i)
    0: return 128'h0000_0000_0000_0000_0000_0000_0800_4500;
    1: return 128'h001C_0000_0000_4001_0000_c0a8_0101_c0a8;
    2: return 128'h0102_0800_0000_0000_0000_0000_0000_0000;
    3: return 128'h0;
    default: return 128'h0;
  endcase
endfunction

module mkPacketParserTest(Empty);
  PacketParserIfc parser <- mkPacketParser;

  Reg#(Bit#(2)) phase <- mkReg(0);
  Reg#(Bit#(3)) feedIdx <- mkReg(0);
  Reg#(Bool) metaChecked <- mkReg(False);
  Reg#(Bit#(3)) payloadCount <- mkReg(0);
  Reg#(Bool) testFail <- mkReg(False);

  rule feed(phase == 0 && feedIdx < 4);
    parser.enq(getTestWord(feedIdx));
    feedIdx <= feedIdx + 1;
  endrule

  rule checkMetaUdp(phase == 0 && feedIdx == 4 && !metaChecked && parser.metaValid);
    let m = parser.metaFirst;
    parser.metaDeq;
    metaChecked <= True;
    if (m.protocol != 17 || m.srcPort != 12345 || m.dstPort != 54321 ||
        m.totalLength != 50 || m.srcIp != 32'hc0a80101 || m.dstIp != 32'hc0a80102 ||
        m.payloadOffset != 42 || m.payloadLength != 22)
      testFail <= True;
  endrule

  rule drainPayloadUdp(phase == 0 && metaChecked && payloadCount < 4 && parser.payloadValid);
    let w = parser.payloadFirst;
    parser.payloadDeq;
    if (w != getTestWord(zeroExtend(payloadCount)))
      testFail <= True;
    payloadCount <= payloadCount + 1;
  endrule

  rule startIcmpPhase(phase == 0 && metaChecked && payloadCount == 4);
    phase <= 1;
    feedIdx <= 0;
    metaChecked <= False;
    payloadCount <= 0;
  endrule

  rule feedIcmp(phase == 1 && feedIdx < 4);
    parser.enq(getTestWordIcmp(feedIdx));
    feedIdx <= feedIdx + 1;
  endrule

  rule checkMetaIcmp(phase == 1 && feedIdx == 4 && !metaChecked && parser.metaValid);
    let m = parser.metaFirst;
    parser.metaDeq;
    metaChecked <= True;
    if (m.protocol != 1 || m.srcPort != 0 || m.dstPort != 0 ||
        m.totalLength != 28 || m.srcIp != 32'hc0a80101 || m.dstIp != 32'hc0a80102 ||
        m.payloadOffset != 42 || m.payloadLength != 0)
      testFail <= True;
  endrule

  rule drainPayloadIcmp(phase == 1 && metaChecked && payloadCount < 3 && parser.payloadValid);
    let w = parser.payloadFirst;
    parser.payloadDeq;
    if (w != getTestWordIcmp(zeroExtend(payloadCount)))
      testFail <= True;
    payloadCount <= payloadCount + 1;
  endrule

  rule done(phase == 1 && metaChecked && payloadCount == 3);
    if (testFail)
      $display("FAIL: PacketParser meta or payload mismatch");
    else
      $display("PASS: PacketParser TCP/UDP/ICMP");
    $finish(0);
  endrule
endmodule

endpackage: PacketParser
