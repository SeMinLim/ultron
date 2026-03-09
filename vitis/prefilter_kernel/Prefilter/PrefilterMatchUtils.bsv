package PrefilterMatchUtils;

function Bit#(8) getWordByteUtils(Bit#(64) inputWord, Integer byteIndexFromMsb);
  Integer shiftAmount = (7 - byteIndexFromMsb) * 8;
  return truncate(inputWord >> shiftAmount);
endfunction

function Bit#(64) fnv1a64(Bit#(64) pattern, Bit#(8) len);
  Bit#(64) h = 64'hcbf29ce484222325;
  for (Integer i = 0; i < 8; i = i + 1) begin
    Bit#(8) b = getWordByteUtils(pattern, i);
    if (fromInteger(i) < len) begin
      h = (h ^ zeroExtend(b)) * 64'h100000001b3;
    end
  end
  return h;
endfunction

function Bool validPatternLen1to8(Bit#(8) len);
  return len >= 1 && len <= 8;
endfunction

function Bit#(3) bucketForLen1to8(Bit#(8) len);
  Bit#(3) out = 0;
  if (len == 0) begin
    out = 0;
  end else if (len > 8) begin
    out = 7;
  end else begin
    out = truncate(len - 1);
  end
  return out;
endfunction

function Bit#(64) msbMaskByLen(Bit#(8) len);
  Bit#(64) m = 0;
  for (Integer i = 0; i < 8; i = i + 1) begin
    Bit#(8) idx = fromInteger(i);
    if (idx < len) begin
      m = m | (64'hff << ((7 - i) * 8));
    end
  end
  return m;
endfunction

function Bit#(64) normalizePatternByLen(Bit#(64) pattern, Bit#(8) len);
  return pattern & msbMaskByLen(len);
endfunction

function Bit#(64) windowKeyByStartLen(Bit#(64) payload64, Bit#(4) start, Bit#(8) len);
  Bit#(6) shiftBytes = zeroExtend(start);
  Bit#(10) shiftBits = zeroExtend(shiftBytes) << 3;
  Bit#(64) shifted = payload64 << shiftBits;
  return shifted & msbMaskByLen(len);
endfunction

endpackage: PrefilterMatchUtils
