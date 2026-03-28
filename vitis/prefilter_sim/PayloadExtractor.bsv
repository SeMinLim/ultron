

package PayloadExtractor;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import PcieCtrl::*;
import PacketParserTypes::*;

interface PayloadExtractorIfc;

    method Action putPacketWord(DMAWord word);
    

    method Action putMeta(PacketMeta meta);
    

    method Bool payloadAvailable;
    method Bit#(256) getPayload;
    method Action deqPayload;
endinterface

module mkPayloadExtractor(PayloadExtractorIfc);
    FIFOF#(DMAWord) packetWordQ <- mkFIFOF;
    FIFOF#(PacketMeta) metaQ <- mkFIFOF;
    FIFOF#(Bit#(256)) payloadOutQ <- mkFIFOF;
    
    Reg#(Bit#(16)) wordCount <- mkReg(0);
    Reg#(Bit#(16)) payloadWordsRemaining <- mkReg(0);
    Reg#(Maybe#(Bit#(128))) accumulator <- mkReg(tagged Invalid);
    Reg#(Bool) inPayload <- mkReg(False);
    Reg#(Bit#(16)) currentOffset <- mkReg(0);
    Reg#(Bit#(16)) payloadStart <- mkReg(0);
    Reg#(Bit#(16)) payloadLen <- mkReg(0);
    

    rule processPacket (packetWordQ.notEmpty && metaQ.notEmpty);
        let word = packetWordQ.first;
        

        if (!inPayload) begin
            let meta = metaQ.first;
            metaQ.deq;
            
            payloadStart <= meta.payloadOffset;
            payloadLen <= meta.payloadLength;
            currentOffset <= 0;
            inPayload <= True;
            wordCount <= 0;
            accumulator <= tagged Invalid;
            

            Bit#(16) totalBytes = meta.payloadOffset + meta.payloadLength;
            Bit#(16) totalWords = (totalBytes + 15) >> 4;
            payloadWordsRemaining <= totalWords;
        end
        

        Bit#(16) byteOffset = wordCount << 4;
        

        if (byteOffset + 16 > payloadStart && byteOffset < (payloadStart + payloadLen)) begin

            
            if (byteOffset >= payloadStart) begin

                if (accumulator matches tagged Invalid) begin
                    accumulator <= tagged Valid word;
                end else begin

                    Bit#(256) payload256 = {word, fromMaybe(0, accumulator)};
                    payloadOutQ.enq(payload256);
                    accumulator <= tagged Invalid;
                end
            end
        end
        
        packetWordQ.deq;
        wordCount <= wordCount + 1;
        

        if (wordCount + 1 >= payloadWordsRemaining) begin
            inPayload <= False;
            

            if (accumulator matches tagged Valid .lastWord) begin
                Bit#(256) payload256 = {128'b0, lastWord};
                payloadOutQ.enq(payload256);
                accumulator <= tagged Invalid;
            end
        end
    endrule
    
    method Action putPacketWord(DMAWord word);
        packetWordQ.enq(word);
    endmethod
    
    method Action putMeta(PacketMeta meta);
        metaQ.enq(meta);
    endmethod
    
    method Bool payloadAvailable;
        return payloadOutQ.notEmpty;
    endmethod
    
    method Bit#(256) getPayload;
        return payloadOutQ.first;
    endmethod
    
    method Action deqPayload;
        payloadOutQ.deq;
    endmethod
endmodule

endpackage: PayloadExtractor
