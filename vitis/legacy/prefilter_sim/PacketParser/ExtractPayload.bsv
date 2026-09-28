package ExtractPayload;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import PcieCtrl::*;
import PacketParserTypes::*;

interface ExtractPayloadIfc;
    method Action putPacketWord(DMAWord word);
    method Action putMeta(PacketMeta meta);
    method Bool payloadReady;
    method Bit#(256) getPayload;
    method Action deqPayload;
endinterface

module mkExtractPayload(ExtractPayloadIfc);
    FIFOF#(DMAWord) wordQ <- mkFIFOF;
    FIFOF#(PacketMeta) metaQ <- mkFIFOF;
    FIFOF#(Bit#(256)) payloadQ <- mkFIFOF;

    Reg#(Bool) processingPacket <- mkReg(False);
    Reg#(Bit#(16)) currentByteOffset <- mkReg(0);
    Reg#(PacketMeta) currentMeta <- mkRegU;

    Reg#(Bit#(256)) payloadBuffer <- mkReg(0);
    Reg#(Bit#(6)) bufferFillLevel <- mkReg(0);

    function Bit#(128) lowByteMask(Bit#(5) nBytes);
        case (nBytes)
            0:  return 128'h0;
            1:  return 128'h000000000000000000000000000000FF;
            2:  return 128'h0000000000000000000000000000FFFF;
            3:  return 128'h00000000000000000000000000FFFFFF;
            4:  return 128'h000000000000000000000000FFFFFFFF;
            5:  return 128'h0000000000000000000000FFFFFFFFFF;
            6:  return 128'h00000000000000000000FFFFFFFFFFFF;
            7:  return 128'h000000000000000000FFFFFFFFFFFFFF;
            8:  return 128'h0000000000000000FFFFFFFFFFFFFFFF;
            9:  return 128'h00000000000000FFFFFFFFFFFFFFFFFF;
            10: return 128'h000000000000FFFFFFFFFFFFFFFFFFFF;
            11: return 128'h0000000000FFFFFFFFFFFFFFFFFFFFFF;
            12: return 128'h00000000FFFFFFFFFFFFFFFFFFFFFFFF;
            13: return 128'h000000FFFFFFFFFFFFFFFFFFFFFFFFFF;
            14: return 128'h0000FFFFFFFFFFFFFFFFFFFFFFFFFFFF;
            15: return 128'h00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
            default: return 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        endcase
    endfunction

    rule processWord (wordQ.notEmpty && (processingPacket || metaQ.notEmpty) && payloadQ.notFull);
        let word = wordQ.first;
        wordQ.deq;

        PacketMeta activeMeta = currentMeta;
        Bit#(16) wordStart = currentByteOffset;
        if (!processingPacket) begin
            activeMeta = metaQ.first;
            metaQ.deq;
            wordStart = 0;
        end

        Bit#(16) wordEnd = wordStart + 16;
        Bit#(16) payloadStart = activeMeta.payloadOffset;
        Bit#(16) payloadEnd = activeMeta.payloadOffset + activeMeta.payloadLength;

        Bit#(256) newBuffer = payloadBuffer;
        Bit#(6) fillLevel = bufferFillLevel;
        Bool emittedChunk = False;

        Bit#(16) clipStart = (wordStart > payloadStart) ? wordStart : payloadStart;
        Bit#(16) clipEnd = (wordEnd < payloadEnd) ? wordEnd : payloadEnd;

        if (clipEnd > clipStart) begin
            Bit#(5) nBytes = truncate(clipEnd - clipStart);
            Bit#(4) startByteInWord = truncate(clipStart - wordStart);
            Bit#(8) startShiftBits = zeroExtend(startByteInWord) << 3;

            Bit#(128) shiftedWord = word >> startShiftBits;
            Bit#(128) maskedWord = shiftedWord & lowByteMask(nBytes);

            Bit#(6) totalBytes = fillLevel + zeroExtend(nBytes);
            if (totalBytes < 32) begin
                Bit#(9) fillShiftBits = zeroExtend(fillLevel) << 3;
                newBuffer = newBuffer | (zeroExtend(maskedWord) << fillShiftBits);
                fillLevel = totalBytes;
            end else begin
                Bit#(5) firstPartBytes = truncate(32 - fillLevel);
                Bit#(5) remainBytes = nBytes - firstPartBytes;

                Bit#(128) firstPartMask = lowByteMask(firstPartBytes);
                Bit#(128) firstPart = maskedWord & firstPartMask;
                Bit#(9) fillShiftBits = zeroExtend(fillLevel) << 3;
                Bit#(256) outChunk = newBuffer | (zeroExtend(firstPart) << fillShiftBits);
                payloadQ.enq(outChunk);
                emittedChunk = True;

                if (remainBytes > 0) begin
                    Bit#(8) remainShiftBits = zeroExtend(firstPartBytes) << 3;
                    Bit#(128) remainPart = (maskedWord >> remainShiftBits) & lowByteMask(remainBytes);
                    newBuffer = zeroExtend(remainPart);
                    fillLevel = zeroExtend(remainBytes);
                end else begin
                    newBuffer = 0;
                    fillLevel = 0;
                end
            end
        end

        if (wordEnd >= payloadEnd) begin
            if (fillLevel > 0 && !emittedChunk) begin
                payloadQ.enq(newBuffer);
                fillLevel = 0;
                newBuffer = 0;
            end

            processingPacket <= False;
            currentByteOffset <= 0;
            currentMeta <= activeMeta;
            payloadBuffer <= newBuffer;
            bufferFillLevel <= fillLevel;
        end else begin
            processingPacket <= True;
            currentByteOffset <= wordEnd;
            currentMeta <= activeMeta;
            payloadBuffer <= newBuffer;
            bufferFillLevel <= fillLevel;
        end
    endrule

    method Action putPacketWord(DMAWord word);
        wordQ.enq(word);
    endmethod

    method Action putMeta(PacketMeta meta);
        metaQ.enq(meta);
    endmethod

    method Bool payloadReady;
        return payloadQ.notEmpty;
    endmethod

    method Bit#(256) getPayload;
        return payloadQ.first;
    endmethod

    method Action deqPayload;
        payloadQ.deq;
    endmethod
endmodule

endpackage: ExtractPayload
