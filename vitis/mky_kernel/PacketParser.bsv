import FIFO::*;
import FIFOF::*;
import SpecialFIFOs::*;

typedef enum {
    Eth,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Payload,
    Drop
} ParseState deriving (Bits, Eq, FShow);

interface PacketParserIfc;
    method Action putByte(Bit#(8) b, Bool last);
    method ActionValue#(Tuple2#(Bit#(8), Bool)) getPayloadByte;
    method Bool payloadNotEmpty;
    method Bool inputNotEmpty;
    method Bool canPut;
endinterface

module mkPacketParser(PacketParserIfc);
    FIFOF#(Tuple2#(Bit#(8), Bool)) outQ <- mkPipelineFIFOF;

    Reg#(ParseState) state <- mkReg(Eth);
    Reg#(Bit#(8)) cnt <- mkReg(0);
    Reg#(Bit#(8)) hdrEnd <- mkReg(0);
    Reg#(Bit#(8)) proto <- mkReg(0);
    Reg#(Bit#(8)) ethHi <- mkReg(0);

    function ParseState nextL4(Bit#(8) p);
        case (p)
            8'd6: return Tcp;
            8'd17: return Udp;
            8'd1: return Icmp;
            8'd58: return Icmp;
            default: return Payload;
        endcase
    endfunction

    method Action putByte(Bit#(8) b, Bool last) if ((state != Payload) || outQ.notFull);
        if (last) begin
            if (state == Payload) outQ.enq(tuple2(b, True));
            state <= Eth;
            cnt <= 0;
        end else begin
            case (state)
                Eth: begin
                    if (cnt == 12) begin
                        ethHi <= b;
                        cnt <= 13;
                    end else if (cnt == 13) begin
                        Bit#(16) etype = {ethHi, b};
                        cnt <= 0;
                        case (etype)
                            16'h0800: state <= Ipv4;
                            16'h86DD: state <= Ipv6;
                            default: state <= Drop;
                        endcase
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Ipv4: begin
                    if (cnt == 0) begin
                        Bit#(8) ihl = zeroExtend(b[3:0]);
                        hdrEnd <= (ihl << 2) - 1;
                        cnt <= 1;
                    end else if (cnt == 9) begin
                        proto <= b;
                        cnt <= 10;
                    end else begin
                        if (cnt == hdrEnd) begin
                            state <= nextL4(proto);
                            cnt <= 0;
                        end else begin
                            cnt <= cnt + 1;
                        end
                    end
                end

                Ipv6: begin
                    if (cnt == 6) proto <= b;
                    if (cnt == 39) begin
                        state <= nextL4(proto);
                        cnt <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Tcp: begin
                    if (cnt == 12) begin
                        Bit#(8) doff = zeroExtend(b[7:4]);
                        hdrEnd <= (doff << 2) - 1;
                        cnt <= 13;
                    end else if (cnt > 12) begin
                        if (cnt == hdrEnd) begin
                            state <= Payload;
                            cnt <= 0;
                        end else begin
                            cnt <= cnt + 1;
                        end
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Udp: begin
                    if (cnt == 7) begin
                        state <= Payload;
                        cnt <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Icmp: begin
                    if (cnt == 7) begin
                        state <= Payload;
                        cnt <= 0;
                    end else begin
                        cnt <= cnt + 1;
                    end
                end

                Payload: begin
                    outQ.enq(tuple2(b, False));
                end

                Drop: begin
                end
            endcase
        end
    endmethod

    method ActionValue#(Tuple2#(Bit#(8), Bool)) getPayloadByte if (outQ.notEmpty);
        let p = outQ.first;
        outQ.deq;
        return p;
    endmethod

    method Bool payloadNotEmpty = outQ.notEmpty;
    method Bool inputNotEmpty = False;
    method Bool canPut = (state != Payload) || outQ.notFull;
endmodule
