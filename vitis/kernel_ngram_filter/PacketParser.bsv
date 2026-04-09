package PacketParser;

import FIFO::*;
import FIFOF::*;
import SpecialFIFOs::*;

typedef enum {
    Eth,
    Ipv4,
    Ipv6,
    Ipv6Ext,
    Tcp,
    Udp,
    Icmp,
    Payload,
    Drop
} ParseState deriving (Bits, Eq, FShow);

interface PacketParserIfc;
    method Action   putByte(Bit#(8) b, Bool last);
    method Bool     inPayload;
    method Bit#(8)  getProto;
    method Bit#(16) getSrcPort;
    method Bit#(16) getDstPort;
    method Bit#(8)  getIcmpType;
    method Bit#(8)  getIcmpCode;
    method Bool     isTcp;
    method Bool     isUdp;
    method Bool     isIcmp;
endinterface

module mkPacketParser(PacketParserIfc);
    Reg#(ParseState) state <- mkReg(Eth);
    Reg#(Bit#(8)) cnt    <- mkReg(0);
    Reg#(Bit#(8)) hdrEnd <- mkReg(0);
    Reg#(Bit#(8)) proto  <- mkReg(0);
    Reg#(Bit#(8)) ethHi  <- mkReg(0);
    Reg#(Bit#(8)) extNext <- mkReg(0);

    Reg#(Bit#(8))  pktSrcHi  <- mkReg(0);
    Reg#(Bit#(8))  pktSrcLo  <- mkReg(0);
    Reg#(Bit#(8))  pktDstHi  <- mkReg(0);
    Reg#(Bit#(8))  pktDstLo  <- mkReg(0);
    Reg#(Bit#(8))  pktIcmpT  <- mkReg(0);
    Reg#(Bit#(8))  pktIcmpC  <- mkReg(0);
    Reg#(Bool)     pktIsTcp  <- mkReg(False);
    Reg#(Bool)     pktIsUdp  <- mkReg(False);
    Reg#(Bool)     pktIsIcmp <- mkReg(False);

    function Bool isIpv6ExtHdr(Bit#(8) p);
        case (p)
            8'd0:  return True;
            8'd43: return True;
            8'd44: return True;
            8'd60: return True;
            8'd51: return True;
            default: return False;
        endcase
    endfunction

    function ParseState nextL4(Bit#(8) p);
        case (p)
            8'd6:  return Tcp;
            8'd17: return Udp;
            8'd1:  return Icmp;
            8'd58: return Icmp;
            default: return Drop;
        endcase
    endfunction

    method Action putByte(Bit#(8) b, Bool last);
        if (last) begin
            state <= Eth;
            cnt   <= 0;
        end else begin
            case (state)
                Eth: begin
                    if (cnt == 12) begin
                        ethHi <= b;
                        cnt   <= 13;
                    end else if (cnt == 13) begin
                        Bit#(16) etype = {ethHi, b};
                        cnt <= 0;
                        case (etype)
                            16'h0800: state <= Ipv4;
                            16'h86DD: state <= Ipv6;
                            default:  state <= Drop;
                        endcase
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Ipv4: begin
                    if (cnt == 0) begin
                        Bit#(8) ihl = zeroExtend(b[3:0]);
                        hdrEnd <= (ihl << 2) - 1;
                        cnt    <= 1;
                    end else if (cnt == 9) begin
                        proto <= b;
                        cnt   <= 10;
                    end else begin
                        if (cnt == hdrEnd) begin
                            state <= nextL4(proto);
                            cnt   <= 0;
                        end else begin
                            cnt <= cnt + 1;
                        end
                    end
                end

                Ipv6: begin
                    if (cnt == 6) proto <= b;
                    if (cnt == 39) begin
                        if (isIpv6ExtHdr(proto)) begin
                            state <= Ipv6Ext;
                        end else begin
                            state <= nextL4(proto);
                        end
                        cnt <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Ipv6Ext: begin
                    if (cnt == 0) begin
                        extNext <= b;
                        cnt     <= 1;
                    end else if (cnt == 1) begin
                        Bool ok     = True;
                        Bit#(8) endPos = 0;
                        if (proto == 8'd44) begin
                            endPos = 8'd7;
                        end else if (proto == 8'd0 || proto == 8'd43 || proto == 8'd60) begin
                            Bit#(9) total = (zeroExtend(b) + 1) << 3;
                            if (total < 9'd8 || total > 9'd255) begin
                                ok = False;
                            end else begin
                                endPos = truncate(total - 1);
                            end
                        end else if (proto == 8'd51) begin
                            Bit#(10) total = (zeroExtend(b) + 2) << 2;
                            if (total < 10'd8 || total > 10'd255) begin
                                ok = False;
                            end else begin
                                endPos = truncate(total - 1);
                            end
                        end else begin
                            ok = False;
                        end
                        if (ok) begin
                            hdrEnd <= endPos;
                            cnt    <= 2;
                        end else begin
                            state <= Drop;
                            cnt   <= 0;
                        end
                    end else begin
                        if (cnt == hdrEnd) begin
                            proto <= extNext;
                            if (isIpv6ExtHdr(extNext)) begin
                                state <= Ipv6Ext;
                            end else begin
                                state <= nextL4(extNext);
                            end
                            cnt <= 0;
                        end else begin
                            cnt <= cnt + 1;
                        end
                    end
                end

                Tcp: begin
                    if (cnt == 12) begin
                        Bit#(8) doff = zeroExtend(b[7:4]);
                        hdrEnd <= (doff << 2) - 1;
                        cnt    <= 13;
                    end else if (cnt > 12) begin
                        if (cnt == hdrEnd) begin
                            state <= Payload;
                            cnt   <= 0;
                        end else begin
                            cnt <= cnt + 1;
                        end
                    end else begin
                        if      (cnt == 0) begin pktSrcHi <= b; pktIsTcp <= True; pktIsUdp <= False; pktIsIcmp <= False; end
                        else if (cnt == 1) pktSrcLo <= b;
                        else if (cnt == 2) pktDstHi <= b;
                        else if (cnt == 3) pktDstLo <= b;
                        cnt <= cnt + 1;
                    end
                end

                Udp: begin
                    if      (cnt == 0) begin pktSrcHi <= b; pktIsTcp <= False; pktIsUdp <= True; pktIsIcmp <= False; end
                    else if (cnt == 1) pktSrcLo <= b;
                    else if (cnt == 2) pktDstHi <= b;
                    else if (cnt == 3) pktDstLo <= b;
                    if (cnt == 7) begin
                        state <= Payload;
                        cnt   <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Icmp: begin
                    if      (cnt == 0) begin pktIcmpT <= b; pktIsTcp <= False; pktIsUdp <= False; pktIsIcmp <= True; end
                    else if (cnt == 1) pktIcmpC <= b;
                    if (cnt == 7) begin
                        state <= Payload;
                        cnt   <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Payload: begin end
                Drop:    begin end
            endcase
        end
    endmethod

    method Bool     inPayload   = (state == Payload);
    method Bit#(8)  getProto    = proto;
    method Bit#(16) getSrcPort  = {pktSrcHi, pktSrcLo};
    method Bit#(16) getDstPort  = {pktDstHi, pktDstLo};
    method Bit#(8)  getIcmpType = pktIcmpT;
    method Bit#(8)  getIcmpCode = pktIcmpC;
    method Bool     isTcp       = pktIsTcp;
    method Bool     isUdp       = pktIsUdp;
    method Bool     isIcmp      = pktIsIcmp;
endmodule

endpackage
