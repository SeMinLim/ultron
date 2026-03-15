// PayloadExtractor: Extracts L4 payload from parsed packets for FPSM
// Uses PacketMeta to skip headers and extract only the payload bytes

package PayloadExtractor;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import PcieCtrl::*;
import PacketParserTypes::*;

// Interface for payload extractor
interface PayloadExtractorIfc;
    // Input: full packet words from PacketParser
    method Action putPacketWord(DMAWord word);
    
    // Input: metadata about where payload starts
    method Action putMeta(PacketMeta meta);
    
    // Output: extracted payload (256-bit chunks for FPSM)
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
    
    // Process incoming packet words and extract payload
    rule processPacket (packetWordQ.notEmpty && metaQ.notEmpty);
        let word = packetWordQ.first;
        
        // Check if this is the first word of a new packet
        if (!inPayload) begin
            let meta = metaQ.first;
            metaQ.deq;
            
            payloadStart <= meta.payloadOffset;
            payloadLen <= meta.payloadLength;
            currentOffset <= 0;
            inPayload <= True;
            wordCount <= 0;
            accumulator <= tagged Invalid;
            
            // Calculate how many 128-bit words we need to process
            // payloadOffset is in bytes, each DMA word is 16 bytes
            Bit#(16) totalBytes = meta.payloadOffset + meta.payloadLength;
            Bit#(16) totalWords = (totalBytes + 15) >> 4; // Divide by 16, round up
            payloadWordsRemaining <= totalWords;
        end
        
        // Current byte offset in packet
        Bit#(16) byteOffset = wordCount << 4; // wordCount * 16
        
        // Check if this word contains any payload data
        if (byteOffset + 16 > payloadStart && byteOffset < (payloadStart + payloadLen)) begin
            // This word contains payload data
            // For simplicity, we'll process full words that are entirely in the payload region
            // or skip if partially overlapping with headers
            
            if (byteOffset >= payloadStart) begin
                // This word is entirely payload (or starts payload)
                if (accumulator matches tagged Invalid) begin
                    accumulator <= tagged Valid word;
                end else begin
                    // We have two 128-bit words, combine into 256 bits
                    Bit#(256) payload256 = {word, fromMaybe(0, accumulator)};
                    payloadOutQ.enq(payload256);
                    accumulator <= tagged Invalid;
                end
            end
        end
        
        packetWordQ.deq;
        wordCount <= wordCount + 1;
        
        // Check if we've processed all words for this packet
        if (wordCount + 1 >= payloadWordsRemaining) begin
            inPayload <= False;
            
            // If we have a pending 128-bit word, output it padded to 256 bits
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
