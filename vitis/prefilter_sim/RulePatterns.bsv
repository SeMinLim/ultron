

typedef 492 NumRules;

typedef struct {
    UInt#(16) ruleId;
    UInt#(16) port;
    UInt#(8)  protocol;
    UInt#(8)  direction;
    UInt#(16) offset;
    UInt#(16) patternLen;
} RuleMeta deriving (Bits, Eq);

function Vector#(NumRules, RuleMeta) getRuleMeta();
    Vector#(NumRules, RuleMeta) meta = newVector;
    meta[0] = RuleMeta {
        ruleId: 0,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[1] = RuleMeta {
        ruleId: 1,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[2] = RuleMeta {
        ruleId: 2,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[3] = RuleMeta {
        ruleId: 3,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 20
    };
    meta[4] = RuleMeta {
        ruleId: 4,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[5] = RuleMeta {
        ruleId: 5,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[6] = RuleMeta {
        ruleId: 6,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 19
    };
    meta[7] = RuleMeta {
        ruleId: 7,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 21
    };
    meta[8] = RuleMeta {
        ruleId: 8,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[9] = RuleMeta {
        ruleId: 9,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[10] = RuleMeta {
        ruleId: 10,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[11] = RuleMeta {
        ruleId: 11,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[12] = RuleMeta {
        ruleId: 12,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 24
    };
    meta[13] = RuleMeta {
        ruleId: 13,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[14] = RuleMeta {
        ruleId: 14,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 52
    };
    meta[15] = RuleMeta {
        ruleId: 15,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[16] = RuleMeta {
        ruleId: 16,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 122
    };
    meta[17] = RuleMeta {
        ruleId: 17,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[18] = RuleMeta {
        ruleId: 18,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 67
    };
    meta[19] = RuleMeta {
        ruleId: 19,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[20] = RuleMeta {
        ruleId: 20,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[21] = RuleMeta {
        ruleId: 21,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 81
    };
    meta[22] = RuleMeta {
        ruleId: 22,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[23] = RuleMeta {
        ruleId: 23,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[24] = RuleMeta {
        ruleId: 24,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[25] = RuleMeta {
        ruleId: 25,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[26] = RuleMeta {
        ruleId: 26,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 21
    };
    meta[27] = RuleMeta {
        ruleId: 27,
        port: 443,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[28] = RuleMeta {
        ruleId: 28,
        port: 443,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[29] = RuleMeta {
        ruleId: 29,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[30] = RuleMeta {
        ruleId: 30,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 95
    };
    meta[31] = RuleMeta {
        ruleId: 31,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[32] = RuleMeta {
        ruleId: 32,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 61
    };
    meta[33] = RuleMeta {
        ruleId: 33,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[34] = RuleMeta {
        ruleId: 34,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[35] = RuleMeta {
        ruleId: 35,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[36] = RuleMeta {
        ruleId: 36,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 76
    };
    meta[37] = RuleMeta {
        ruleId: 37,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[38] = RuleMeta {
        ruleId: 38,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[39] = RuleMeta {
        ruleId: 39,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[40] = RuleMeta {
        ruleId: 40,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[41] = RuleMeta {
        ruleId: 41,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[42] = RuleMeta {
        ruleId: 42,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[43] = RuleMeta {
        ruleId: 43,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[44] = RuleMeta {
        ruleId: 44,
        port: 18080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[45] = RuleMeta {
        ruleId: 45,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 64
    };
    meta[46] = RuleMeta {
        ruleId: 46,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[47] = RuleMeta {
        ruleId: 47,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 69
    };
    meta[48] = RuleMeta {
        ruleId: 48,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[49] = RuleMeta {
        ruleId: 49,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 79
    };
    meta[50] = RuleMeta {
        ruleId: 50,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[51] = RuleMeta {
        ruleId: 51,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 76
    };
    meta[52] = RuleMeta {
        ruleId: 52,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 60
    };
    meta[53] = RuleMeta {
        ruleId: 53,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 84
    };
    meta[54] = RuleMeta {
        ruleId: 54,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[55] = RuleMeta {
        ruleId: 55,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[56] = RuleMeta {
        ruleId: 56,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[57] = RuleMeta {
        ruleId: 57,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[58] = RuleMeta {
        ruleId: 58,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[59] = RuleMeta {
        ruleId: 59,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[60] = RuleMeta {
        ruleId: 60,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 75
    };
    meta[61] = RuleMeta {
        ruleId: 61,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[62] = RuleMeta {
        ruleId: 62,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[63] = RuleMeta {
        ruleId: 63,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 61
    };
    meta[64] = RuleMeta {
        ruleId: 64,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 21
    };
    meta[65] = RuleMeta {
        ruleId: 65,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 61
    };
    meta[66] = RuleMeta {
        ruleId: 66,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 99
    };
    meta[67] = RuleMeta {
        ruleId: 67,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[68] = RuleMeta {
        ruleId: 68,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 71
    };
    meta[69] = RuleMeta {
        ruleId: 69,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 29
    };
    meta[70] = RuleMeta {
        ruleId: 70,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[71] = RuleMeta {
        ruleId: 71,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[72] = RuleMeta {
        ruleId: 72,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[73] = RuleMeta {
        ruleId: 73,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[74] = RuleMeta {
        ruleId: 74,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[75] = RuleMeta {
        ruleId: 75,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[76] = RuleMeta {
        ruleId: 76,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[77] = RuleMeta {
        ruleId: 77,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[78] = RuleMeta {
        ruleId: 78,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[79] = RuleMeta {
        ruleId: 79,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[80] = RuleMeta {
        ruleId: 80,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[81] = RuleMeta {
        ruleId: 81,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[82] = RuleMeta {
        ruleId: 82,
        port: 53413,
        protocol: 17,
        direction: 0,
        offset: 4,
        patternLen: 15
    };
    meta[83] = RuleMeta {
        ruleId: 83,
        port: 9191,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[84] = RuleMeta {
        ruleId: 84,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[85] = RuleMeta {
        ruleId: 85,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[86] = RuleMeta {
        ruleId: 86,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[87] = RuleMeta {
        ruleId: 87,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 62
    };
    meta[88] = RuleMeta {
        ruleId: 88,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[89] = RuleMeta {
        ruleId: 89,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 57
    };
    meta[90] = RuleMeta {
        ruleId: 90,
        port: 8585,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 96
    };
    meta[91] = RuleMeta {
        ruleId: 91,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[92] = RuleMeta {
        ruleId: 92,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[93] = RuleMeta {
        ruleId: 93,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 25
    };
    meta[94] = RuleMeta {
        ruleId: 94,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 105
    };
    meta[95] = RuleMeta {
        ruleId: 95,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[96] = RuleMeta {
        ruleId: 96,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 67
    };
    meta[97] = RuleMeta {
        ruleId: 97,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[98] = RuleMeta {
        ruleId: 98,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 89
    };
    meta[99] = RuleMeta {
        ruleId: 99,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[100] = RuleMeta {
        ruleId: 100,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[101] = RuleMeta {
        ruleId: 101,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[102] = RuleMeta {
        ruleId: 102,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 64
    };
    meta[103] = RuleMeta {
        ruleId: 103,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[104] = RuleMeta {
        ruleId: 104,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[105] = RuleMeta {
        ruleId: 105,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 29
    };
    meta[106] = RuleMeta {
        ruleId: 106,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[107] = RuleMeta {
        ruleId: 107,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 77
    };
    meta[108] = RuleMeta {
        ruleId: 108,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 76
    };
    meta[109] = RuleMeta {
        ruleId: 109,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[110] = RuleMeta {
        ruleId: 110,
        port: 8000,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[111] = RuleMeta {
        ruleId: 111,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[112] = RuleMeta {
        ruleId: 112,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 60
    };
    meta[113] = RuleMeta {
        ruleId: 113,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 108
    };
    meta[114] = RuleMeta {
        ruleId: 114,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[115] = RuleMeta {
        ruleId: 115,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[116] = RuleMeta {
        ruleId: 116,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[117] = RuleMeta {
        ruleId: 117,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[118] = RuleMeta {
        ruleId: 118,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 42
    };
    meta[119] = RuleMeta {
        ruleId: 119,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[120] = RuleMeta {
        ruleId: 120,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[121] = RuleMeta {
        ruleId: 121,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 41
    };
    meta[122] = RuleMeta {
        ruleId: 122,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 55
    };
    meta[123] = RuleMeta {
        ruleId: 123,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[124] = RuleMeta {
        ruleId: 124,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[125] = RuleMeta {
        ruleId: 125,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[126] = RuleMeta {
        ruleId: 126,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[127] = RuleMeta {
        ruleId: 127,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[128] = RuleMeta {
        ruleId: 128,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[129] = RuleMeta {
        ruleId: 129,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[130] = RuleMeta {
        ruleId: 130,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[131] = RuleMeta {
        ruleId: 131,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[132] = RuleMeta {
        ruleId: 132,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[133] = RuleMeta {
        ruleId: 133,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[134] = RuleMeta {
        ruleId: 134,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[135] = RuleMeta {
        ruleId: 135,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[136] = RuleMeta {
        ruleId: 136,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[137] = RuleMeta {
        ruleId: 137,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 75
    };
    meta[138] = RuleMeta {
        ruleId: 138,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 19
    };
    meta[139] = RuleMeta {
        ruleId: 139,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[140] = RuleMeta {
        ruleId: 140,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[141] = RuleMeta {
        ruleId: 141,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[142] = RuleMeta {
        ruleId: 142,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[143] = RuleMeta {
        ruleId: 143,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 55
    };
    meta[144] = RuleMeta {
        ruleId: 144,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 64
    };
    meta[145] = RuleMeta {
        ruleId: 145,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[146] = RuleMeta {
        ruleId: 146,
        port: 5000,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[147] = RuleMeta {
        ruleId: 147,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[148] = RuleMeta {
        ruleId: 148,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 62
    };
    meta[149] = RuleMeta {
        ruleId: 149,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[150] = RuleMeta {
        ruleId: 150,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[151] = RuleMeta {
        ruleId: 151,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[152] = RuleMeta {
        ruleId: 152,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[153] = RuleMeta {
        ruleId: 153,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[154] = RuleMeta {
        ruleId: 154,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[155] = RuleMeta {
        ruleId: 155,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[156] = RuleMeta {
        ruleId: 156,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[157] = RuleMeta {
        ruleId: 157,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 64
    };
    meta[158] = RuleMeta {
        ruleId: 158,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[159] = RuleMeta {
        ruleId: 159,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 43
    };
    meta[160] = RuleMeta {
        ruleId: 160,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 25
    };
    meta[161] = RuleMeta {
        ruleId: 161,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[162] = RuleMeta {
        ruleId: 162,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[163] = RuleMeta {
        ruleId: 163,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 28
    };
    meta[164] = RuleMeta {
        ruleId: 164,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[165] = RuleMeta {
        ruleId: 165,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[166] = RuleMeta {
        ruleId: 166,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[167] = RuleMeta {
        ruleId: 167,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[168] = RuleMeta {
        ruleId: 168,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[169] = RuleMeta {
        ruleId: 169,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[170] = RuleMeta {
        ruleId: 170,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[171] = RuleMeta {
        ruleId: 171,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[172] = RuleMeta {
        ruleId: 172,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[173] = RuleMeta {
        ruleId: 173,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 63
    };
    meta[174] = RuleMeta {
        ruleId: 174,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[175] = RuleMeta {
        ruleId: 175,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[176] = RuleMeta {
        ruleId: 176,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[177] = RuleMeta {
        ruleId: 177,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 79
    };
    meta[178] = RuleMeta {
        ruleId: 178,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 30
    };
    meta[179] = RuleMeta {
        ruleId: 179,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[180] = RuleMeta {
        ruleId: 180,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[181] = RuleMeta {
        ruleId: 181,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[182] = RuleMeta {
        ruleId: 182,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[183] = RuleMeta {
        ruleId: 183,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[184] = RuleMeta {
        ruleId: 184,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[185] = RuleMeta {
        ruleId: 185,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[186] = RuleMeta {
        ruleId: 186,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[187] = RuleMeta {
        ruleId: 187,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[188] = RuleMeta {
        ruleId: 188,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[189] = RuleMeta {
        ruleId: 189,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 18
    };
    meta[190] = RuleMeta {
        ruleId: 190,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[191] = RuleMeta {
        ruleId: 191,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[192] = RuleMeta {
        ruleId: 192,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 33
    };
    meta[193] = RuleMeta {
        ruleId: 193,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 29
    };
    meta[194] = RuleMeta {
        ruleId: 194,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[195] = RuleMeta {
        ruleId: 195,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[196] = RuleMeta {
        ruleId: 196,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[197] = RuleMeta {
        ruleId: 197,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[198] = RuleMeta {
        ruleId: 198,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[199] = RuleMeta {
        ruleId: 199,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 72
    };
    meta[200] = RuleMeta {
        ruleId: 200,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 38
    };
    meta[201] = RuleMeta {
        ruleId: 201,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 31
    };
    meta[202] = RuleMeta {
        ruleId: 202,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 25
    };
    meta[203] = RuleMeta {
        ruleId: 203,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[204] = RuleMeta {
        ruleId: 204,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 66
    };
    meta[205] = RuleMeta {
        ruleId: 205,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 116
    };
    meta[206] = RuleMeta {
        ruleId: 206,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[207] = RuleMeta {
        ruleId: 207,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[208] = RuleMeta {
        ruleId: 208,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 24
    };
    meta[209] = RuleMeta {
        ruleId: 209,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 40
    };
    meta[210] = RuleMeta {
        ruleId: 210,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 30
    };
    meta[211] = RuleMeta {
        ruleId: 212,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[212] = RuleMeta {
        ruleId: 213,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 22
    };
    meta[213] = RuleMeta {
        ruleId: 214,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[214] = RuleMeta {
        ruleId: 215,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 62
    };
    meta[215] = RuleMeta {
        ruleId: 216,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[216] = RuleMeta {
        ruleId: 217,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[217] = RuleMeta {
        ruleId: 218,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[218] = RuleMeta {
        ruleId: 219,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[219] = RuleMeta {
        ruleId: 220,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[220] = RuleMeta {
        ruleId: 221,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[221] = RuleMeta {
        ruleId: 222,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[222] = RuleMeta {
        ruleId: 223,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[223] = RuleMeta {
        ruleId: 224,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[224] = RuleMeta {
        ruleId: 225,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[225] = RuleMeta {
        ruleId: 226,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[226] = RuleMeta {
        ruleId: 227,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[227] = RuleMeta {
        ruleId: 228,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[228] = RuleMeta {
        ruleId: 229,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 54
    };
    meta[229] = RuleMeta {
        ruleId: 230,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[230] = RuleMeta {
        ruleId: 231,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[231] = RuleMeta {
        ruleId: 232,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[232] = RuleMeta {
        ruleId: 233,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[233] = RuleMeta {
        ruleId: 234,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[234] = RuleMeta {
        ruleId: 235,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[235] = RuleMeta {
        ruleId: 236,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[236] = RuleMeta {
        ruleId: 237,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 24
    };
    meta[237] = RuleMeta {
        ruleId: 238,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[238] = RuleMeta {
        ruleId: 239,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[239] = RuleMeta {
        ruleId: 240,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[240] = RuleMeta {
        ruleId: 242,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 60
    };
    meta[241] = RuleMeta {
        ruleId: 243,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[242] = RuleMeta {
        ruleId: 244,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[243] = RuleMeta {
        ruleId: 245,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 84
    };
    meta[244] = RuleMeta {
        ruleId: 246,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[245] = RuleMeta {
        ruleId: 247,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[246] = RuleMeta {
        ruleId: 248,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[247] = RuleMeta {
        ruleId: 249,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[248] = RuleMeta {
        ruleId: 250,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[249] = RuleMeta {
        ruleId: 251,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[250] = RuleMeta {
        ruleId: 252,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[251] = RuleMeta {
        ruleId: 253,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[252] = RuleMeta {
        ruleId: 254,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[253] = RuleMeta {
        ruleId: 255,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[254] = RuleMeta {
        ruleId: 256,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[255] = RuleMeta {
        ruleId: 257,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 54
    };
    meta[256] = RuleMeta {
        ruleId: 258,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 16
    };
    meta[257] = RuleMeta {
        ruleId: 259,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 16
    };
    meta[258] = RuleMeta {
        ruleId: 260,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[259] = RuleMeta {
        ruleId: 261,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[260] = RuleMeta {
        ruleId: 262,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[261] = RuleMeta {
        ruleId: 263,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[262] = RuleMeta {
        ruleId: 264,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 60
    };
    meta[263] = RuleMeta {
        ruleId: 265,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[264] = RuleMeta {
        ruleId: 266,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[265] = RuleMeta {
        ruleId: 267,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[266] = RuleMeta {
        ruleId: 268,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[267] = RuleMeta {
        ruleId: 269,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[268] = RuleMeta {
        ruleId: 270,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 77
    };
    meta[269] = RuleMeta {
        ruleId: 271,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 43
    };
    meta[270] = RuleMeta {
        ruleId: 272,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[271] = RuleMeta {
        ruleId: 273,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 55
    };
    meta[272] = RuleMeta {
        ruleId: 274,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 65
    };
    meta[273] = RuleMeta {
        ruleId: 275,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 65
    };
    meta[274] = RuleMeta {
        ruleId: 276,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[275] = RuleMeta {
        ruleId: 277,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[276] = RuleMeta {
        ruleId: 278,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[277] = RuleMeta {
        ruleId: 279,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[278] = RuleMeta {
        ruleId: 280,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[279] = RuleMeta {
        ruleId: 284,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[280] = RuleMeta {
        ruleId: 285,
        port: 6789,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 24
    };
    meta[281] = RuleMeta {
        ruleId: 286,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[282] = RuleMeta {
        ruleId: 287,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[283] = RuleMeta {
        ruleId: 288,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[284] = RuleMeta {
        ruleId: 289,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[285] = RuleMeta {
        ruleId: 290,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[286] = RuleMeta {
        ruleId: 291,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 71
    };
    meta[287] = RuleMeta {
        ruleId: 292,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[288] = RuleMeta {
        ruleId: 293,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[289] = RuleMeta {
        ruleId: 294,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[290] = RuleMeta {
        ruleId: 295,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[291] = RuleMeta {
        ruleId: 296,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 20
    };
    meta[292] = RuleMeta {
        ruleId: 297,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[293] = RuleMeta {
        ruleId: 298,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[294] = RuleMeta {
        ruleId: 299,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 67
    };
    meta[295] = RuleMeta {
        ruleId: 300,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[296] = RuleMeta {
        ruleId: 301,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[297] = RuleMeta {
        ruleId: 302,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[298] = RuleMeta {
        ruleId: 303,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[299] = RuleMeta {
        ruleId: 304,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[300] = RuleMeta {
        ruleId: 305,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[301] = RuleMeta {
        ruleId: 306,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[302] = RuleMeta {
        ruleId: 307,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[303] = RuleMeta {
        ruleId: 308,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[304] = RuleMeta {
        ruleId: 309,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[305] = RuleMeta {
        ruleId: 310,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 55
    };
    meta[306] = RuleMeta {
        ruleId: 311,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[307] = RuleMeta {
        ruleId: 312,
        port: 7001,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[308] = RuleMeta {
        ruleId: 313,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[309] = RuleMeta {
        ruleId: 314,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[310] = RuleMeta {
        ruleId: 315,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[311] = RuleMeta {
        ruleId: 316,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[312] = RuleMeta {
        ruleId: 317,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[313] = RuleMeta {
        ruleId: 318,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[314] = RuleMeta {
        ruleId: 319,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 91
    };
    meta[315] = RuleMeta {
        ruleId: 320,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[316] = RuleMeta {
        ruleId: 321,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[317] = RuleMeta {
        ruleId: 322,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[318] = RuleMeta {
        ruleId: 323,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[319] = RuleMeta {
        ruleId: 324,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[320] = RuleMeta {
        ruleId: 325,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[321] = RuleMeta {
        ruleId: 326,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[322] = RuleMeta {
        ruleId: 327,
        port: 8080,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[323] = RuleMeta {
        ruleId: 328,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 105
    };
    meta[324] = RuleMeta {
        ruleId: 329,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[325] = RuleMeta {
        ruleId: 330,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[326] = RuleMeta {
        ruleId: 331,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 65
    };
    meta[327] = RuleMeta {
        ruleId: 332,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 34
    };
    meta[328] = RuleMeta {
        ruleId: 333,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[329] = RuleMeta {
        ruleId: 334,
        port: 5000,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[330] = RuleMeta {
        ruleId: 335,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 71
    };
    meta[331] = RuleMeta {
        ruleId: 336,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 62
    };
    meta[332] = RuleMeta {
        ruleId: 337,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 49
    };
    meta[333] = RuleMeta {
        ruleId: 338,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 74
    };
    meta[334] = RuleMeta {
        ruleId: 339,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 23
    };
    meta[335] = RuleMeta {
        ruleId: 340,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 29
    };
    meta[336] = RuleMeta {
        ruleId: 341,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 68
    };
    meta[337] = RuleMeta {
        ruleId: 342,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[338] = RuleMeta {
        ruleId: 343,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[339] = RuleMeta {
        ruleId: 344,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 84
    };
    meta[340] = RuleMeta {
        ruleId: 345,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[341] = RuleMeta {
        ruleId: 346,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[342] = RuleMeta {
        ruleId: 347,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[343] = RuleMeta {
        ruleId: 348,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[344] = RuleMeta {
        ruleId: 349,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[345] = RuleMeta {
        ruleId: 350,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[346] = RuleMeta {
        ruleId: 351,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 75
    };
    meta[347] = RuleMeta {
        ruleId: 352,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[348] = RuleMeta {
        ruleId: 353,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[349] = RuleMeta {
        ruleId: 354,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[350] = RuleMeta {
        ruleId: 355,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[351] = RuleMeta {
        ruleId: 356,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[352] = RuleMeta {
        ruleId: 357,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[353] = RuleMeta {
        ruleId: 358,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[354] = RuleMeta {
        ruleId: 359,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[355] = RuleMeta {
        ruleId: 360,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[356] = RuleMeta {
        ruleId: 361,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[357] = RuleMeta {
        ruleId: 362,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[358] = RuleMeta {
        ruleId: 363,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[359] = RuleMeta {
        ruleId: 364,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[360] = RuleMeta {
        ruleId: 365,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[361] = RuleMeta {
        ruleId: 366,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 48
    };
    meta[362] = RuleMeta {
        ruleId: 367,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[363] = RuleMeta {
        ruleId: 368,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 91
    };
    meta[364] = RuleMeta {
        ruleId: 369,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 47
    };
    meta[365] = RuleMeta {
        ruleId: 370,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[366] = RuleMeta {
        ruleId: 371,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[367] = RuleMeta {
        ruleId: 372,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[368] = RuleMeta {
        ruleId: 373,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[369] = RuleMeta {
        ruleId: 374,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[370] = RuleMeta {
        ruleId: 375,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[371] = RuleMeta {
        ruleId: 376,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[372] = RuleMeta {
        ruleId: 377,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[373] = RuleMeta {
        ruleId: 378,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[374] = RuleMeta {
        ruleId: 379,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[375] = RuleMeta {
        ruleId: 380,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 58
    };
    meta[376] = RuleMeta {
        ruleId: 381,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[377] = RuleMeta {
        ruleId: 382,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 57
    };
    meta[378] = RuleMeta {
        ruleId: 383,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[379] = RuleMeta {
        ruleId: 384,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 29
    };
    meta[380] = RuleMeta {
        ruleId: 385,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 31
    };
    meta[381] = RuleMeta {
        ruleId: 386,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 27
    };
    meta[382] = RuleMeta {
        ruleId: 387,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 30
    };
    meta[383] = RuleMeta {
        ruleId: 388,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[384] = RuleMeta {
        ruleId: 389,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[385] = RuleMeta {
        ruleId: 390,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[386] = RuleMeta {
        ruleId: 391,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[387] = RuleMeta {
        ruleId: 392,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[388] = RuleMeta {
        ruleId: 393,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[389] = RuleMeta {
        ruleId: 394,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 25
    };
    meta[390] = RuleMeta {
        ruleId: 395,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[391] = RuleMeta {
        ruleId: 396,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 66
    };
    meta[392] = RuleMeta {
        ruleId: 397,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[393] = RuleMeta {
        ruleId: 398,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[394] = RuleMeta {
        ruleId: 399,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 66
    };
    meta[395] = RuleMeta {
        ruleId: 400,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 66
    };
    meta[396] = RuleMeta {
        ruleId: 401,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 44
    };
    meta[397] = RuleMeta {
        ruleId: 402,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[398] = RuleMeta {
        ruleId: 403,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[399] = RuleMeta {
        ruleId: 404,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[400] = RuleMeta {
        ruleId: 405,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 80
    };
    meta[401] = RuleMeta {
        ruleId: 406,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 51
    };
    meta[402] = RuleMeta {
        ruleId: 407,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[403] = RuleMeta {
        ruleId: 408,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[404] = RuleMeta {
        ruleId: 409,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[405] = RuleMeta {
        ruleId: 410,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[406] = RuleMeta {
        ruleId: 411,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[407] = RuleMeta {
        ruleId: 412,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[408] = RuleMeta {
        ruleId: 413,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[409] = RuleMeta {
        ruleId: 414,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[410] = RuleMeta {
        ruleId: 415,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[411] = RuleMeta {
        ruleId: 416,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[412] = RuleMeta {
        ruleId: 417,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 29
    };
    meta[413] = RuleMeta {
        ruleId: 418,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[414] = RuleMeta {
        ruleId: 419,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[415] = RuleMeta {
        ruleId: 420,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[416] = RuleMeta {
        ruleId: 421,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[417] = RuleMeta {
        ruleId: 422,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[418] = RuleMeta {
        ruleId: 423,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[419] = RuleMeta {
        ruleId: 424,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[420] = RuleMeta {
        ruleId: 425,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 41
    };
    meta[421] = RuleMeta {
        ruleId: 426,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 35
    };
    meta[422] = RuleMeta {
        ruleId: 427,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 33
    };
    meta[423] = RuleMeta {
        ruleId: 428,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[424] = RuleMeta {
        ruleId: 429,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 34
    };
    meta[425] = RuleMeta {
        ruleId: 430,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[426] = RuleMeta {
        ruleId: 431,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 42
    };
    meta[427] = RuleMeta {
        ruleId: 432,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[428] = RuleMeta {
        ruleId: 433,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[429] = RuleMeta {
        ruleId: 434,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 18
    };
    meta[430] = RuleMeta {
        ruleId: 435,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[431] = RuleMeta {
        ruleId: 436,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[432] = RuleMeta {
        ruleId: 437,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[433] = RuleMeta {
        ruleId: 438,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[434] = RuleMeta {
        ruleId: 439,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 33
    };
    meta[435] = RuleMeta {
        ruleId: 440,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[436] = RuleMeta {
        ruleId: 441,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 69
    };
    meta[437] = RuleMeta {
        ruleId: 442,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 26
    };
    meta[438] = RuleMeta {
        ruleId: 443,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 70
    };
    meta[439] = RuleMeta {
        ruleId: 444,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 76
    };
    meta[440] = RuleMeta {
        ruleId: 445,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 21
    };
    meta[441] = RuleMeta {
        ruleId: 446,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 30
    };
    meta[442] = RuleMeta {
        ruleId: 447,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 18
    };
    meta[443] = RuleMeta {
        ruleId: 448,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[444] = RuleMeta {
        ruleId: 449,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[445] = RuleMeta {
        ruleId: 450,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[446] = RuleMeta {
        ruleId: 451,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 27
    };
    meta[447] = RuleMeta {
        ruleId: 452,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 38
    };
    meta[448] = RuleMeta {
        ruleId: 453,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 21
    };
    meta[449] = RuleMeta {
        ruleId: 454,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 41
    };
    meta[450] = RuleMeta {
        ruleId: 455,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 59
    };
    meta[451] = RuleMeta {
        ruleId: 456,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 57
    };
    meta[452] = RuleMeta {
        ruleId: 457,
        port: 7201,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 17
    };
    meta[453] = RuleMeta {
        ruleId: 458,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[454] = RuleMeta {
        ruleId: 459,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[455] = RuleMeta {
        ruleId: 460,
        port: 1337,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 45
    };
    meta[456] = RuleMeta {
        ruleId: 461,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 27
    };
    meta[457] = RuleMeta {
        ruleId: 463,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[458] = RuleMeta {
        ruleId: 466,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 62
    };
    meta[459] = RuleMeta {
        ruleId: 467,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 32
    };
    meta[460] = RuleMeta {
        ruleId: 468,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 67
    };
    meta[461] = RuleMeta {
        ruleId: 469,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[462] = RuleMeta {
        ruleId: 470,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 39
    };
    meta[463] = RuleMeta {
        ruleId: 471,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 38
    };
    meta[464] = RuleMeta {
        ruleId: 472,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 50
    };
    meta[465] = RuleMeta {
        ruleId: 473,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 40
    };
    meta[466] = RuleMeta {
        ruleId: 474,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[467] = RuleMeta {
        ruleId: 475,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[468] = RuleMeta {
        ruleId: 476,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[469] = RuleMeta {
        ruleId: 477,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 31
    };
    meta[470] = RuleMeta {
        ruleId: 478,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 55
    };
    meta[471] = RuleMeta {
        ruleId: 479,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 36
    };
    meta[472] = RuleMeta {
        ruleId: 480,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 37
    };
    meta[473] = RuleMeta {
        ruleId: 481,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 41
    };
    meta[474] = RuleMeta {
        ruleId: 482,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 24
    };
    meta[475] = RuleMeta {
        ruleId: 483,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[476] = RuleMeta {
        ruleId: 484,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 52
    };
    meta[477] = RuleMeta {
        ruleId: 485,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 56
    };
    meta[478] = RuleMeta {
        ruleId: 486,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 46
    };
    meta[479] = RuleMeta {
        ruleId: 487,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 24
    };
    meta[480] = RuleMeta {
        ruleId: 488,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 67
    };
    meta[481] = RuleMeta {
        ruleId: 489,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 77
    };
    meta[482] = RuleMeta {
        ruleId: 490,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 53
    };
    meta[483] = RuleMeta {
        ruleId: 491,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[484] = RuleMeta {
        ruleId: 492,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 32
    };
    meta[485] = RuleMeta {
        ruleId: 493,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 21
    };
    meta[486] = RuleMeta {
        ruleId: 494,
        port: 80,
        protocol: 6,
        direction: 0,
        offset: 4,
        patternLen: 28
    };
    meta[487] = RuleMeta {
        ruleId: 495,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 36
    };
    meta[488] = RuleMeta {
        ruleId: 496,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 36
    };
    meta[489] = RuleMeta {
        ruleId: 497,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 36
    };
    meta[490] = RuleMeta {
        ruleId: 498,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 37
    };
    meta[491] = RuleMeta {
        ruleId: 499,
        port: 80,
        protocol: 6,
        direction: 1,
        offset: 4,
        patternLen: 23
    };
    return meta;
endfunction

function Vector#(NumRules, Vector#(32, Bit#(8))) getRulePatterns();
    Vector#(NumRules, Vector#(32, Bit#(8))) patterns = newVector;
    patterns[0] = vec(8'h2f, 8'h64, 8'h65, 8'h66, 8'h65, 8'h63, 8'h74, 8'h2f, 8'h64, 8'h65, 8'h66, 8'h65, 8'h63, 8'h74, 8'h73, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h6e, 8'h61, 8'h6d);
    patterns[1] = vec(8'h2f, 8'h70, 8'h72, 8'h6f, 8'h6a, 8'h65, 8'h63, 8'h74, 8'h73, 8'h65, 8'h6e, 8'h64, 8'h2d, 8'h72, 8'h31, 8'h36, 8'h30, 8'h35, 8'h2f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70);
    patterns[2] = vec(8'h2f, 8'h62, 8'h6c, 8'h6f, 8'h6f, 8'h64, 8'h62, 8'h61, 8'h6e, 8'h6b, 8'h2f, 8'h61, 8'h62, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[3] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h61, 8'h70, 8'h69, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h3c, 8'h73, 8'h63, 8'h72, 8'h69, 8'h70, 8'h74, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[4] = vec(8'h2f, 8'h63, 8'h75, 8'h73, 8'h74, 8'h6f, 8'h6d, 8'h65, 8'h72, 8'h5f, 8'h73, 8'h75, 8'h70, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h64, 8'h65, 8'h70, 8'h61, 8'h72, 8'h74, 8'h6d);
    patterns[5] = vec(8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2e, 8'h64, 8'h6f, 8'h3f, 8'h6a, 8'h76, 8'h61, 8'h72, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h74, 8'h69, 8'h74, 8'h6c, 8'h65, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[6] = vec(8'h26, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h6e, 8'h66, 8'h65, 8'h7a, 8'h32, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[7] = vec(8'h61, 8'h73, 8'h65, 8'h5f, 8'h63, 8'h6f, 8'h6e, 8'h66, 8'h69, 8'h67, 8'h26, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h3d, 8'h60, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[8] = vec(8'h2f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h2f, 8'h41, 8'h7a, 8'h75, 8'h72, 8'h65, 8'h52, 8'h65, 8'h64, 8'h69, 8'h72, 8'h65, 8'h63, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72, 8'h3d, 8'h26, 8'h65);
    patterns[9] = vec(8'h43, 8'h6f, 8'h6e, 8'h74, 8'h72, 8'h6f, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h48, 8'h74, 8'h6d, 8'h6c, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h78, 8'h73, 8'h6c, 8'h43, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h3d, 8'h26, 8'h69);
    patterns[10] = vec(8'h2f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h2f, 8'h4f, 8'h6e, 8'h65, 8'h64, 8'h72, 8'h69, 8'h76, 8'h65, 8'h52, 8'h65, 8'h64, 8'h69, 8'h72, 8'h65, 8'h63, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72);
    patterns[11] = vec(8'h2f, 8'h65, 8'h78, 8'h61, 8'h6d, 8'h2f, 8'h66, 8'h65, 8'h65, 8'h64, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h71, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[12] = vec(8'h2f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h2f, 8'h66, 8'h61, 8'h69, 8'h6c, 8'h75, 8'h72, 8'h65, 8'h3f, 8'h70, 8'h72, 8'h6f, 8'h76, 8'h69, 8'h64, 8'h65, 8'h72, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[13] = vec(8'h2f, 8'h72, 8'h65, 8'h73, 8'h6f, 8'h75, 8'h72, 8'h63, 8'h65, 8'h73, 8'h2f, 8'h71, 8'h6d, 8'h63, 8'h2f, 8'h66, 8'h6f, 8'h6e, 8'h74, 8'h73, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[14] = vec(8'h41, 8'h6c, 8'h62, 8'h61, 8'h62, 8'h61, 8'h74, 8'h2e, 8'h65, 8'h6b, 8'h65, 8'h79, 8'h41, 8'h6c, 8'h62, 8'h61, 8'h62, 8'h61, 8'h74, 8'h2e, 8'h6b, 8'h65, 8'h79, 8'h41, 8'h6c, 8'h62, 8'h61, 8'h62, 8'h61, 8'h74, 8'h5f, 8'h53);
    patterns[15] = vec(8'h2f, 8'h6f, 8'h70, 8'h6e, 8'h73, 8'h65, 8'h6e, 8'h73, 8'h65, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h5f, 8'h63, 8'h65, 8'h72, 8'h74, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70);
    patterns[16] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h70, 8'h64, 8'h66, 8'h2d, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h74, 8'h6f);
    patterns[17] = vec(8'h72, 8'h6f, 8'h75, 8'h74, 8'h65, 8'h5f, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h77, 8'h65, 8'h65, 8'h6b, 8'h6c, 8'h79, 8'h5f, 8'h61, 8'h70, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h6d, 8'h65, 8'h6e);
    patterns[18] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[19] = vec(8'h2f, 8'h77, 8'h6f, 8'h6e, 8'h64, 8'h65, 8'h72, 8'h63, 8'h6d, 8'h73, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h55);
    patterns[20] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h73, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2f, 8'h2e, 8'h2e, 8'h2f);
    patterns[21] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2d, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61);
    patterns[22] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h77, 8'h73, 8'h2f, 8'h6d, 8'h73, 8'h77, 8'h2f, 8'h74, 8'h65, 8'h6e, 8'h61, 8'h6e, 8'h74, 8'h2f, 8'h25, 8'h32, 8'h37, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[23] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h74, 8'h6f, 8'h74, 8'h70, 8'h2f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h2d, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h75, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h64, 8'h65, 8'h2f, 8'h2e, 8'h2e);
    patterns[24] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h61, 8'h76, 8'h2f, 8'h63, 8'h6c, 8'h69, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f);
    patterns[25] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h6d, 8'h69, 8'h66, 8'h73, 8'h2f, 8'h61, 8'h73, 8'h66, 8'h56, 8'h33, 8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h32, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[26] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h6d, 8'h69, 8'h66, 8'h73, 8'h2f, 8'h61, 8'h61, 8'h64, 8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h32, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[27] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h74, 8'h6f, 8'h74, 8'h70, 8'h2f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h2d, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h75, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h64, 8'h65, 8'h2f, 8'h2e, 8'h2e);
    patterns[28] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h61, 8'h76, 8'h2f, 8'h63, 8'h6c, 8'h69, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f);
    patterns[29] = vec(8'h70, 8'h6f, 8'h73, 8'h74, 8'h2d, 8'h6e, 8'h65, 8'h77, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h66, 8'h6f, 8'h6f, 8'h67, 8'h61, 8'h6c, 8'h6c, 8'h65, 8'h72);
    patterns[30] = vec(8'h74, 8'h68, 8'h69, 8'h73, 8'h2e, 8'h63, 8'h6f, 8'h6e, 8'h73, 8'h74, 8'h72, 8'h75, 8'h63, 8'h74, 8'h6f, 8'h72, 8'h2e, 8'h63, 8'h6f, 8'h6e, 8'h73, 8'h74, 8'h72, 8'h75, 8'h63, 8'h74, 8'h6f, 8'h72, 8'h28, 8'h22, 8'h72, 8'h65);
    patterns[31] = vec(8'h2f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h73, 8'h75, 8'h72, 8'h76, 8'h65, 8'h79, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e);
    patterns[32] = vec(8'h73, 8'h69, 8'h74, 8'h65, 8'h6d, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h72, 8'h61, 8'h67, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h73, 8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2e, 8'h66, 8'h63, 8'h63, 8'h3f);
    patterns[33] = vec(8'h26, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h64, 8'h69, 8'h74, 8'h74, 8'h79, 8'h5f, 8'h65, 8'h78, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h26, 8'h74, 8'h61, 8'h62, 8'h3d, 8'h65, 8'h78, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h5f, 8'h64, 8'h69);
    patterns[34] = vec(8'h2e, 8'h61, 8'h6b, 8'h69, 8'h72, 8'h61, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h61, 8'h6b, 8'h69, 8'h72, 8'h61, 8'h5f, 8'h72, 8'h65, 8'h61, 8'h64, 8'h6d, 8'h65, 8'h2e, 8'h74, 8'h78, 8'h74);
    patterns[35] = vec(8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h74, 8'h65, 8'h72, 8'h5b, 8'h62, 8'h72, 8'h61, 8'h6e, 8'h64, 8'h69, 8'h64, 8'h5d, 8'h3d, 8'h76, 8'h6e, 8'h78, 8'h6a, 8'h62, 8'h22, 8'h00, 8'h00);
    patterns[36] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[37] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h65, 8'h65, 8'h70, 8'h73, 8'h6f, 8'h26);
    patterns[38] = vec(8'h2f, 8'h43, 8'h6f, 8'h6e, 8'h66, 8'h69, 8'h67, 8'h75, 8'h72, 8'h65, 8'h52, 8'h65, 8'h63, 8'h6f, 8'h76, 8'h65, 8'h72, 8'h79, 8'h53, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h2f, 8'h47, 8'h45, 8'h54, 8'h5f, 8'h50);
    patterns[39] = vec(8'h2f, 8'h77, 8'h65, 8'h62, 8'h2f, 8'h73, 8'h65, 8'h74, 8'h5f, 8'h70, 8'h72, 8'h6f, 8'h66, 8'h69, 8'h6c, 8'h69, 8'h6e, 8'h67, 8'h3f, 8'h70, 8'h72, 8'h6f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h3d, 8'h30, 8'h26, 8'h63, 8'h6f, 8'h6c);
    patterns[40] = vec(8'h76, 8'h65, 8'h68, 8'h69, 8'h63, 8'h6c, 8'h65, 8'h2f, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h75, 8'h70, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h56, 8'h55, 8'h5f, 8'h49, 8'h44);
    patterns[41] = vec(8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2d, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h66, 8'h61, 8'h74, 8'h74, 8'h2d, 8'h32, 8'h34);
    patterns[42] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h61, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61, 8'h63, 8'h74, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h41, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61, 8'h63, 8'h74, 8'h3f, 8'h61, 8'h72, 8'h74);
    patterns[43] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h72, 8'h69, 8'h2d, 8'h63, 8'h66, 8'h37);
    patterns[44] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h72, 8'h6f, 8'h62, 8'h6f, 8'h74, 8'h2f, 8'h61, 8'h70, 8'h70, 8'h72, 8'h6f, 8'h76, 8'h61, 8'h6c, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h3f, 8'h65, 8'h6e, 8'h74, 8'h69, 8'h74);
    patterns[45] = vec(8'h2f, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2f, 8'h61, 8'h74, 8'h74, 8'h65, 8'h6e, 8'h64, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h2f, 8'h61, 8'h73, 8'h6b, 8'h5f, 8'h64);
    patterns[46] = vec(8'h2f, 8'h63, 8'h73, 8'h76, 8'h53, 8'h65, 8'h72, 8'h76, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h67, 8'h65, 8'h74, 8'h4c, 8'h69, 8'h73, 8'h74, 8'h3d, 8'h31, 8'h26, 8'h64, 8'h69, 8'h72, 8'h3d, 8'h2e, 8'h2e, 8'h2f);
    patterns[47] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h6c, 8'h70, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h2f, 8'h61, 8'h72, 8'h63, 8'h68, 8'h69, 8'h76, 8'h65, 8'h2d, 8'h63);
    patterns[48] = vec(8'h2f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h5f, 8'h62, 8'h75, 8'h69, 8'h6c, 8'h64, 8'h65, 8'h72, 8'h2f, 8'h70, 8'h72, 8'h65, 8'h76, 8'h69, 8'h65, 8'h77, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h5f, 8'h69);
    patterns[49] = vec(8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h72, 8'h6f, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h3d, 8'h70, 8'h6a, 8'h46, 8'h72, 8'h6f, 8'h6e, 8'h74, 8'h26, 8'h61, 8'h63, 8'h74);
    patterns[50] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h68, 8'h61, 8'h73, 8'h70, 8'h2d, 8'h6c, 8'h69);
    patterns[51] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h63, 8'h2d, 8'h73, 8'h65, 8'h74, 8'h74);
    patterns[52] = vec(8'h2f, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2f, 8'h65, 8'h6d, 8'h61, 8'h69, 8'h6c, 8'h2f, 8'h69, 8'h6e, 8'h62, 8'h6f, 8'h78, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h5f, 8'h77, 8'h65, 8'h62, 8'h6d);
    patterns[53] = vec(8'h2f, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h65, 8'h6e, 8'h64, 8'h2f, 8'h6e, 8'h6f, 8'h74, 8'h69, 8'h66, 8'h69, 8'h63, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h5f, 8'h61, 8'h63);
    patterns[54] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h72, 8'h6f, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h73, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h6c, 8'h61, 8'h79, 8'h65, 8'h72, 8'h5f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h6f, 8'h72);
    patterns[55] = vec(8'h41, 8'h76, 8'h61, 8'h6c, 8'h61, 8'h6e, 8'h63, 8'h68, 8'h65, 8'h57, 8'h65, 8'h62, 8'h2f, 8'h2f, 8'h66, 8'h61, 8'h63, 8'h65, 8'h73, 8'h2f, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h78, 8'h2e, 8'h66, 8'h61, 8'h63, 8'h65, 8'h73, 8'h2e);
    patterns[56] = vec(8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h75, 8'h72, 8'h63, 8'h68, 8'h61, 8'h73, 8'h65, 8'h5f, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h62, 8'h6f, 8'h2e);
    patterns[57] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[58] = vec(8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h2f, 8'h75, 8'h69, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h65, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h64, 8'h2f, 8'h25, 8'h33, 8'h43, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[59] = vec(8'h2f, 8'h70, 8'h68, 8'h70, 8'h2d, 8'h6c, 8'h66, 8'h69, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h5f, 8'h69, 8'h6e, 8'h66);
    patterns[60] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h62, 8'h61, 8'h6e, 8'h6e, 8'h65, 8'h72, 8'h5f, 8'h6d, 8'h65, 8'h73, 8'h73, 8'h61, 8'h67, 8'h65, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h68, 8'h65, 8'h6c, 8'h70, 8'h65, 8'h72);
    patterns[61] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h6f, 8'h6f, 8'h5f, 8'h64, 8'h69, 8'h73, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h5f, 8'h72, 8'h75, 8'h6c);
    patterns[62] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2d, 8'h61, 8'h72);
    patterns[63] = vec(8'h2f, 8'h6c, 8'h69, 8'h6e, 8'h6b, 8'h77, 8'h65, 8'h63, 8'h68, 8'h61, 8'h74, 8'h2d, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h6f, 8'h6e, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2f);
    patterns[64] = vec(8'h20, 8'h2f, 8'h73, 8'h6f, 8'h61, 8'h70, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h3d, 8'h26, 8'h26, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[65] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[66] = vec(8'h2f, 8'h78, 8'h77, 8'h69, 8'h6b, 8'h69, 8'h2f, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h2f, 8'h58, 8'h57, 8'h69, 8'h6b, 8'h69, 8'h2f, 8'h4d, 8'h61, 8'h69, 8'h6e, 8'h3f, 8'h78, 8'h70, 8'h61, 8'h67, 8'h65);
    patterns[67] = vec(8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h5f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[68] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[69] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h77, 8'h6f, 8'h6f, 8'h66, 8'h2d, 8'h73, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h26, 8'h65, 8'h64, 8'h69, 8'h74, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00);
    patterns[70] = vec(8'h2f, 8'h74, 8'h6f, 8'h75, 8'h72, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6f, 8'h70, 8'h65, 8'h72, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h70, 8'h61, 8'h79, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h2e, 8'h70);
    patterns[71] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h75, 8'h6e, 8'h69, 8'h71, 8'h75, 8'h65, 8'h5f);
    patterns[72] = vec(8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2d, 8'h74, 8'h72, 8'h61, 8'h63, 8'h6b, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h72, 8'h61, 8'h63, 8'h6b, 8'h65, 8'h72, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00);
    patterns[73] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6e, 8'h6a, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2d, 8'h67, 8'h6f, 8'h6f, 8'h67, 8'h6c, 8'h65, 8'h2d, 8'h73, 8'h68, 8'h65, 8'h65, 8'h74, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h66, 8'h69, 8'h67, 8'h26);
    patterns[74] = vec(8'h63, 8'h6f, 8'h6e, 8'h6e, 8'h65, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h70, 8'h3d, 8'h31, 8'h32, 8'h37, 8'h2e, 8'h30, 8'h2e, 8'h30, 8'h2e, 8'h31);
    patterns[75] = vec(8'h2f, 8'h70, 8'h6d, 8'h73, 8'h3f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h3d, 8'h6c, 8'h6f, 8'h67, 8'h67, 8'h69, 8'h6e, 8'h67, 8'h26, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h5f, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h2e, 8'h2e);
    patterns[76] = vec(8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2d, 8'h73, 8'h74, 8'h75, 8'h64, 8'h65, 8'h6e, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h73, 8'h74, 8'h75, 8'h64, 8'h65, 8'h6e, 8'h74, 8'h3d, 8'h33, 8'h27, 8'h00, 8'h00);
    patterns[77] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h64, 8'h72, 8'h61, 8'h67, 8'h2d, 8'h6e, 8'h2d, 8'h64, 8'h72, 8'h6f, 8'h70, 8'h2d, 8'h75, 8'h70, 8'h6c, 8'h6f, 8'h61);
    patterns[78] = vec(8'h2f, 8'h68, 8'h6f, 8'h6d, 8'h65, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h3f, 8'h71, 8'h75, 8'h65, 8'h72, 8'h79, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[79] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h5f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h5f, 8'h70, 8'h72, 8'h6f, 8'h63, 8'h65, 8'h73, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h5f, 8'h70);
    patterns[80] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h71, 8'h75, 8'h69, 8'h7a, 8'h2d, 8'h6d, 8'h61, 8'h6b, 8'h65, 8'h72, 8'h2d, 8'h73, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h26, 8'h61, 8'h79, 8'h73, 8'h5f, 8'h71, 8'h75, 8'h69);
    patterns[81] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h68, 8'h6f, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h62, 8'h6f, 8'h78, 8'h2f, 8'h72, 8'h65, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h3f, 8'h62, 8'h65, 8'h66, 8'h6f, 8'h72, 8'h65);
    patterns[82] = vec(8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h6e, 8'h65, 8'h74, 8'h63, 8'h6f, 8'h72, 8'h65, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[83] = vec(8'h2f, 8'h64, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h2d, 8'h77, 8'h65, 8'h62, 8'h2f, 8'h6b, 8'h6f, 8'h6e, 8'h69, 8'h63, 8'h61, 8'h2f, 8'h69, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2f, 8'h25, 8'h33, 8'h43, 8'h00, 8'h00);
    patterns[84] = vec(8'h2f, 8'h65, 8'h76, 8'h61, 8'h6c, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h74, 8'h61, 8'h73, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31);
    patterns[85] = vec(8'h2f, 8'h66, 8'h75, 8'h72, 8'h6e, 8'h69, 8'h74, 8'h75, 8'h72, 8'h65, 8'h5f, 8'h6d, 8'h61, 8'h73, 8'h74, 8'h65, 8'h72, 8'h2f, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h49, 8'h6e, 8'h66, 8'h6f, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70);
    patterns[86] = vec(8'h26, 8'h73, 8'h68, 8'h6f, 8'h72, 8'h74, 8'h63, 8'h6f, 8'h64, 8'h65, 8'h3d, 8'h5b, 8'h43, 8'h61, 8'h6c, 8'h65, 8'h6e, 8'h64, 8'h61, 8'h72, 8'h69, 8'h6f, 8'h5f, 8'h41, 8'h76, 8'h69, 8'h72, 8'h61, 8'h74, 8'h6f, 8'h20, 8'h69);
    patterns[87] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h79, 8'h69, 8'h6b, 8'h65, 8'h73, 8'h2d, 8'h6d);
    patterns[88] = vec(8'h2f, 8'h73, 8'h68, 8'h6f, 8'h70, 8'h2f, 8'h3f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h3d, 8'h73, 8'h68, 8'h6f, 8'h70, 8'h26, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68);
    patterns[89] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h63, 8'h6c, 8'h6f, 8'h75, 8'h64, 8'h2d, 8'h67);
    patterns[90] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h3b, 8'h76, 8'h31, 8'h25, 8'h32, 8'h66, 8'h75, 8'h73, 8'h65, 8'h72, 8'h73, 8'h25, 8'h32, 8'h66, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2f, 8'h65, 8'h76, 8'h65, 8'h6e, 8'h74);
    patterns[91] = vec(8'h2f, 8'h70, 8'h69, 8'h73, 8'h70, 8'h2f, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h2f, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h6f, 8'h75, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h74, 8'h3d, 8'h5c, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[92] = vec(8'h2f, 8'h63, 8'h6f, 8'h6c, 8'h6c, 8'h65, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2f, 8'h61, 8'h6c, 8'h6c, 8'h3f, 8'h74, 8'h61, 8'h67, 8'h3d, 8'h74, 8'h73, 8'h68, 8'h69, 8'h72, 8'h74, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[93] = vec(8'h2f, 8'h6b, 8'h65, 8'h65, 8'h70, 8'h61, 8'h6c, 8'h69, 8'h76, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h61, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[94] = vec(8'h2f, 8'h77, 8'h5f, 8'h73, 8'h65, 8'h6c, 8'h66, 8'h73, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h2f, 8'h6f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h73, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h2f, 8'h25, 8'h32, 8'h65, 8'h2e);
    patterns[95] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h5f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h64, 8'h65, 8'h6c, 8'h26, 8'h66);
    patterns[96] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[97] = vec(8'h68, 8'h65, 8'h6c, 8'h70, 8'h69, 8'h65, 8'h5f, 8'h66, 8'h61, 8'h71, 8'h5f, 8'h67, 8'h72, 8'h6f, 8'h75, 8'h70, 8'h26, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h68, 8'h65, 8'h6c, 8'h70, 8'h69);
    patterns[98] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h69, 8'h6e, 8'h61);
    patterns[99] = vec(8'h2f, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h75, 8'h63, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h26, 8'h26, 8'h61, 8'h72, 8'h74, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h25, 8'h33, 8'h43, 8'h00);
    patterns[100] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h44, 8'h69, 8'h61, 8'h53, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h2f, 8'h47, 8'h65, 8'h74, 8'h44, 8'h49, 8'h41, 8'h43, 8'h6c, 8'h6f, 8'h75, 8'h64, 8'h4c, 8'h69, 8'h73, 8'h74);
    patterns[101] = vec(8'h72, 8'h65, 8'h73, 8'h70, 8'h6f, 8'h6e, 8'h73, 8'h65, 8'h45, 8'h6e, 8'h74, 8'h72, 8'h79, 8'h50, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h26, 8'h65, 8'h76, 8'h65, 8'h6e, 8'h74, 8'h3d, 8'h31, 8'h26, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h67);
    patterns[102] = vec(8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h63, 8'h66, 8'h37, 8'h26, 8'h70, 8'h6f);
    patterns[103] = vec(8'h2f, 8'h74, 8'h6f, 8'h75, 8'h72, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6f, 8'h70, 8'h65, 8'h72, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h65, 8'h78, 8'h70, 8'h65, 8'h6e, 8'h73, 8'h65, 8'h2e, 8'h70);
    patterns[104] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h75, 8'h74, 8'h6f, 8'h6d, 8'h61, 8'h74);
    patterns[105] = vec(8'h2f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h2f, 8'h70, 8'h64, 8'h66, 8'h5f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h3f, 8'h4a, 8'h4f, 8'h42, 8'h49, 8'h44, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00, 8'h00);
    patterns[106] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h72, 8'h61, 8'h6e, 8'h6b, 8'h73, 8'h26, 8'h75, 8'h72, 8'h6c, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[107] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h70, 8'h6f, 8'h6c, 8'h69, 8'h63, 8'h69, 8'h65, 8'h73, 8'h2f, 8'h76, 8'h61, 8'h6c, 8'h69, 8'h64, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2f, 8'h63, 8'h6f, 8'h6e, 8'h64);
    patterns[108] = vec(8'h2f, 8'h6c, 8'h75, 8'h6d, 8'h69, 8'h73, 8'h2f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h2f, 8'h68, 8'h74, 8'h6d, 8'h6c, 8'h65, 8'h76, 8'h61, 8'h6c, 8'h75, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2f, 8'h55, 8'h72);
    patterns[109] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h26, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h78, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[110] = vec(8'h2f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h6d, 8'h65, 8'h73, 8'h73, 8'h61, 8'h67, 8'h69, 8'h6e, 8'h67, 8'h2f, 8'h43, 8'h3a, 8'h2e, 8'h2e, 8'h2f, 8'h43, 8'h3a, 8'h2e, 8'h2e, 8'h2f, 8'h43, 8'h3a, 8'h2e);
    patterns[111] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h69, 8'h6d, 8'h70, 8'h6c, 8'h65, 8'h61, 8'h6c, 8'h5f, 8'h73, 8'h6c, 8'h69, 8'h64, 8'h65, 8'h72, 8'h5f, 8'h73, 8'h68, 8'h6f, 8'h77, 8'h26, 8'h61, 8'h63, 8'h74, 8'h69, 8'h76, 8'h65);
    patterns[112] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h67, 8'h68, 8'h5f, 8'h63, 8'h6f, 8'h6e, 8'h74);
    patterns[113] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h62, 8'h77, 8'h6c, 8'h2d, 8'h61, 8'h64, 8'h76, 8'h61);
    patterns[114] = vec(8'h2f, 8'h3f, 8'h77, 8'h63, 8'h2d, 8'h61, 8'h70, 8'h69, 8'h3d, 8'h70, 8'h61, 8'h79, 8'h70, 8'h6c, 8'h75, 8'h73, 8'h5f, 8'h67, 8'h61, 8'h74, 8'h65, 8'h77, 8'h61, 8'h79, 8'h26, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h5f);
    patterns[115] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h73, 8'h77, 8'h61, 8'h67, 8'h67, 8'h65, 8'h72, 8'h75, 8'h69, 8'h2f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h69, 8'h63, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[116] = vec(8'h2f, 8'h69, 8'h61, 8'h6d, 8'h2f, 8'h69, 8'h6d, 8'h2f, 8'h65, 8'h77, 8'h73, 8'h63, 8'h2f, 8'h53, 8'h25, 8'h33, 8'h63, 8'h73, 8'h74, 8'h79, 8'h6c, 8'h65, 8'h3e, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[117] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h6d, 8'h65, 8'h73, 8'h68, 8'h73, 8'h79, 8'h6e, 8'h63, 8'h2f, 8'h72, 8'h65, 8'h73, 8'h6f, 8'h75, 8'h72, 8'h63, 8'h65, 8'h73, 8'h3f, 8'h6f);
    patterns[118] = vec(8'h4c, 8'h59, 8'h4e, 8'h58, 8'h00, 8'h00, 8'h00, 8'h00, 8'h4c, 8'h00, 8'h59, 8'h00, 8'h4e, 8'h00, 8'h58, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h36, 8'h36, 8'h61, 8'h32, 8'h30, 8'h34, 8'h61, 8'h65, 8'h65, 8'h37, 8'h38, 8'h36);
    patterns[119] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h6e, 8'h69, 8'h6d, 8'h61, 8'h74, 8'h65, 8'h64, 8'h5f, 8'h61, 8'h6c, 8'h5f, 8'h73, 8'h68, 8'h6f, 8'h77, 8'h26, 8'h61, 8'h63, 8'h74, 8'h69, 8'h76, 8'h65, 8'h3d, 8'h30, 8'h26, 8'h70);
    patterns[120] = vec(8'h2f, 8'h6d, 8'h61, 8'h69, 8'h6c, 8'h69, 8'h6e, 8'h73, 8'h70, 8'h65, 8'h63, 8'h74, 8'h6f, 8'h72, 8'h2f, 8'h70, 8'h75, 8'h62, 8'h6c, 8'h69, 8'h63, 8'h2f, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70);
    patterns[121] = vec(8'h00, 8'h43, 8'h00, 8'h79, 8'h00, 8'h62, 8'h00, 8'h65, 8'h00, 8'h72, 8'h00, 8'h56, 8'h00, 8'h6f, 8'h00, 8'h6c, 8'h00, 8'h6b, 8'h00, 8'h5f, 8'h00, 8'h52, 8'h00, 8'h65, 8'h00, 8'h61, 8'h00, 8'h64, 8'h00, 8'h4d, 8'h00, 8'h65);
    patterns[122] = vec(8'h3f, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h75, 8'h63, 8'h74, 8'h3d, 8'h5f, 8'h5f, 8'h49, 8'h4e, 8'h53, 8'h45, 8'h52, 8'h54, 8'h5f, 8'h50, 8'h52, 8'h4f, 8'h44, 8'h55, 8'h43, 8'h54, 8'h5f, 8'h50, 8'h41, 8'h47, 8'h45, 8'h5f, 8'h26);
    patterns[123] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h2d, 8'h62, 8'h72, 8'h6f, 8'h77, 8'h73, 8'h65, 8'h72, 8'h2d, 8'h73, 8'h6e, 8'h61, 8'h70, 8'h73, 8'h68, 8'h6f, 8'h74, 8'h2f, 8'h3f, 8'h73, 8'h6e, 8'h61, 8'h70, 8'h73);
    patterns[124] = vec(8'h2f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h65, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h74, 8'h3d, 8'h28, 8'h00);
    patterns[125] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h62, 8'h6f, 8'h72, 8'h72, 8'h6f, 8'h77, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h5f, 8'h62, 8'h6f, 8'h72, 8'h72, 8'h6f, 8'h77, 8'h26);
    patterns[126] = vec(8'h2f, 8'h64, 8'h6f, 8'h6b, 8'h75, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h73, 8'h6f, 8'h63, 8'h3a, 8'h66, 8'h72, 8'h6f, 8'h6e, 8'h74, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3a, 8'h74, 8'h69, 8'h6d, 8'h65);
    patterns[127] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2f, 8'h6c, 8'h61, 8'h6e, 8'h67, 8'h3f, 8'h6c, 8'h61, 8'h6e, 8'h67, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[128] = vec(8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h65, 8'h78, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d);
    patterns[129] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h6e, 8'h67, 8'h64, 8'h75, 8'h63, 8'h74, 8'h75, 8'h6e);
    patterns[130] = vec(8'h3f, 8'h73, 8'h6f, 8'h72, 8'h74, 8'h46, 8'h69, 8'h65, 8'h6c, 8'h64, 8'h3d, 8'h63, 8'h75, 8'h73, 8'h74, 8'h6f, 8'h6d, 8'h65, 8'h72, 8'h4e, 8'h61, 8'h6d, 8'h65, 8'h26, 8'h73, 8'h6f, 8'h72, 8'h74, 8'h4f, 8'h72, 8'h64, 8'h65);
    patterns[131] = vec(8'h2f, 8'h73, 8'h63, 8'h68, 8'h6f, 8'h6f, 8'h6c, 8'h2d, 8'h74, 8'h61, 8'h73, 8'h6b, 8'h2d, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h2f, 8'h65, 8'h6e, 8'h64, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h2f, 8'h64, 8'h65);
    patterns[132] = vec(8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2d, 8'h74, 8'h69, 8'h6d, 8'h65, 8'h73, 8'h68, 8'h65, 8'h65, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h69, 8'h6d, 8'h65, 8'h73, 8'h68, 8'h65, 8'h65, 8'h74, 8'h3d);
    patterns[133] = vec(8'h2f, 8'h63, 8'h6f, 8'h64, 8'h61, 8'h2f, 8'h66, 8'h72, 8'h61, 8'h6d, 8'h65, 8'h73, 8'h65, 8'h74, 8'h3f, 8'h63, 8'h6f, 8'h6c, 8'h73, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[134] = vec(8'h2f, 8'h75, 8'h69, 8'h2f, 8'h2e, 8'h2e, 8'h5c, 8'h73, 8'h72, 8'h63, 8'h5c, 8'h67, 8'h65, 8'h74, 8'h53, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h2e, 8'h72, 8'h73, 8'h62, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[135] = vec(8'h2f, 8'h4c, 8'h6f, 8'h67, 8'h2f, 8'h44, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2f, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h5c, 8'h2e, 8'h2e, 8'h5c, 8'h00, 8'h00);
    patterns[136] = vec(8'h3d, 8'h49, 8'h6e, 8'h76, 8'h6f, 8'h69, 8'h63, 8'h65, 8'h26, 8'h76, 8'h69, 8'h65, 8'h77, 8'h3d, 8'h4c, 8'h69, 8'h73, 8'h74, 8'h26, 8'h61, 8'h70, 8'h70, 8'h3d, 8'h49, 8'h4e, 8'h56, 8'h45, 8'h4e, 8'h54, 8'h4f, 8'h52, 8'h59);
    patterns[137] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[138] = vec(8'h20, 8'h53, 8'h33, 8'h50, 8'h34, 8'h4e, 8'h44, 8'h20, 8'h72, 8'h61, 8'h6e, 8'h73, 8'h6f, 8'h6d, 8'h77, 8'h61, 8'h72, 8'h65, 8'h21, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[139] = vec(8'h2f, 8'h70, 8'h68, 8'h70, 8'h2d, 8'h73, 8'h71, 8'h6c, 8'h69, 8'h74, 8'h65, 8'h2d, 8'h76, 8'h6d, 8'h73, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h76, 8'h69, 8'h73);
    patterns[140] = vec(8'h2f, 8'h6d, 8'h6c, 8'h69, 8'h52, 8'h65, 8'h61, 8'h6c, 8'h74, 8'h69, 8'h6d, 8'h65, 8'h45, 8'h6d, 8'h61, 8'h69, 8'h6c, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65, 8'h78, 8'h65, 8'h3d, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c);
    patterns[141] = vec(8'h2f, 8'h6f, 8'h70, 8'h65, 8'h6e, 8'h63, 8'h6c, 8'h69, 8'h6e, 8'h69, 8'h63, 8'h2f, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h2e, 8'h64, 8'h6f, 8'h3f, 8'h50, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00);
    patterns[142] = vec(8'h2f, 8'h72, 8'h61, 8'h63, 8'h65, 8'h72, 8'h2d, 8'h72, 8'h65, 8'h73, 8'h75, 8'h6c, 8'h74, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h72, 8'h61, 8'h63, 8'h65, 8'h72, 8'h69, 8'h64, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[143] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h53, 8'h55, 8'h4c, 8'h6c, 8'h79, 8'h44, 8'h61);
    patterns[144] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h68, 8'h6f, 8'h6d, 8'h65, 8'h26, 8'h64, 8'h6f, 8'h3d, 8'h73, 8'h68, 8'h6f, 8'h70, 8'h3a, 8'h69, 8'h6e, 8'h64, 8'h65);
    patterns[145] = vec(8'h2f, 8'h73, 8'h63, 8'h68, 8'h6f, 8'h6f, 8'h6c, 8'h2d, 8'h74, 8'h61, 8'h73, 8'h6b, 8'h2d, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h2f, 8'h65, 8'h6e, 8'h64, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h2f, 8'h64, 8'h65);
    patterns[146] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h32, 8'h2e, 8'h30, 8'h2f, 8'h6d, 8'h6c, 8'h66, 8'h6c, 8'h6f, 8'h77, 8'h2d, 8'h61, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61, 8'h63, 8'h74, 8'h73, 8'h2f, 8'h61, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61);
    patterns[147] = vec(8'h2f, 8'h70, 8'h6b, 8'h66, 8'h61, 8'h63, 8'h65, 8'h62, 8'h6f, 8'h6f, 8'h6b, 8'h2f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2f, 8'h66, 8'h61, 8'h63, 8'h65, 8'h62, 8'h6f, 8'h6f, 8'h6b, 8'h43, 8'h6f, 8'h6e, 8'h6e, 8'h65, 8'h63, 8'h74);
    patterns[148] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[149] = vec(8'h61, 8'h47, 8'h56, 8'h73, 8'h63, 8'h47, 8'h52, 8'h6c, 8'h63, 8'h32, 8'h74, 8'h4a, 8'h62, 8'h6e, 8'h52, 8'h6c, 8'h5a, 8'h33, 8'h4a, 8'h68, 8'h64, 8'h47, 8'h6c, 8'h76, 8'h62, 8'h6c, 8'h56, 8'h7a, 8'h5a, 8'h58, 8'h49, 8'h36);
    patterns[150] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h72, 8'h65, 8'h6d, 8'h6d, 8'h65, 8'h72);
    patterns[151] = vec(8'h2f, 8'h68, 8'h72, 8'h6d, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h72, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h72, 8'h79, 8'h3d, 8'h53);
    patterns[152] = vec(8'h2f, 8'h6a, 8'h73, 8'h2f, 8'h70, 8'h6c, 8'h61, 8'h79, 8'h65, 8'h72, 8'h2f, 8'h64, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h79, 8'h65, 8'h72, 8'h2f, 8'h64, 8'h6d, 8'h6b, 8'h75, 8'h2f, 8'h3f, 8'h61, 8'h63, 8'h3d, 8'h64, 8'h65, 8'h6c);
    patterns[153] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h75, 8'h63, 8'h74, 8'h2f, 8'h73, 8'h70, 8'h65, 8'h63, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h3f, 8'h73, 8'h70, 8'h65, 8'h63, 8'h5f, 8'h67);
    patterns[154] = vec(8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h65, 8'h74, 8'h2d, 8'h6d, 8'h75, 8'h73, 8'h69, 8'h63, 8'h2d, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f);
    patterns[155] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h4d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h26, 8'h69, 8'h64);
    patterns[156] = vec(8'h2f, 8'h75, 8'h70, 8'h67, 8'h72, 8'h61, 8'h64, 8'h65, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h74, 8'h65, 8'h72, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h74, 8'h68, 8'h3d, 8'h68, 8'h74, 8'h74, 8'h70, 8'h3a, 8'h2f, 8'h2f);
    patterns[157] = vec(8'h2f, 8'h75, 8'h63, 8'h6c, 8'h77, 8'h70, 8'h2d, 8'h64, 8'h61, 8'h73, 8'h68, 8'h62, 8'h6f, 8'h61, 8'h72, 8'h64, 8'h2f, 8'h3f, 8'h75, 8'h63, 8'h6c, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h69);
    patterns[158] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h69, 8'h6e, 8'h67, 8'h3b, 8'h65, 8'h63, 8'h68, 8'h6f, 8'h24, 8'h49, 8'h46, 8'h53, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[159] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h73, 8'h70, 8'h78, 8'h6d, 8'h6c, 8'h2f, 8'h47, 8'h65, 8'h74, 8'h4c, 8'h61, 8'h72, 8'h67, 8'h65, 8'h46, 8'h69, 8'h65, 8'h6c, 8'h64, 8'h3f, 8'h43, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74);
    patterns[160] = vec(8'h2f, 8'h47, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h44, 8'h6f, 8'h63, 8'h73, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h78, 8'h3f, 8'h72, 8'h70, 8'h74, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[161] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h72, 8'h6f, 8'h62, 8'h6f, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h31, 8'h26, 8'h73, 8'h69, 8'h64, 8'h65, 8'h62, 8'h61, 8'h72, 8'h3d);
    patterns[162] = vec(8'h2f, 8'h6f, 8'h72, 8'h6f, 8'h6e, 8'h6c, 8'h69, 8'h6e, 8'h65, 8'h2f, 8'h73, 8'h74, 8'h2f, 8'h41, 8'h6e, 8'h6d, 8'h65, 8'h6c, 8'h64, 8'h65, 8'h6e, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h69, 8'h6e, 8'h70, 8'h75, 8'h74, 8'h55);
    patterns[163] = vec(8'h09, 8'h46, 8'h75, 8'h6e, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h10, 8'h55, 8'h6e, 8'h69, 8'h74, 8'h49, 8'h6e, 8'h6a, 8'h65, 8'h63, 8'h74, 8'h53, 8'h65, 8'h72, 8'h76, 8'h65, 8'h72, 8'h11, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[164] = vec(8'h2f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6d, 8'h65, 8'h73, 8'h73, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[165] = vec(8'h2f, 8'h65, 8'h6e, 8'h64, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2d, 8'h63, 8'h61, 8'h6c, 8'h6f, 8'h72, 8'h69, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h61, 8'h6c);
    patterns[166] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h6c, 8'h65, 8'h61, 8'h72, 8'h6e, 8'h70, 8'h72, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h3f, 8'h63);
    patterns[167] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h64, 8'h73, 8'h63, 8'h66, 8'h37, 8'h5f, 8'h72, 8'h65, 8'h66, 8'h72, 8'h65, 8'h73, 8'h68, 8'h63, 8'h61, 8'h70, 8'h74, 8'h63, 8'h68, 8'h61, 8'h26, 8'h74, 8'h61, 8'h67, 8'h6e);
    patterns[168] = vec(8'h2f, 8'h6e, 8'h65, 8'h74, 8'h77, 8'h6f, 8'h72, 8'h6b, 8'h44, 8'h69, 8'h61, 8'h67, 8'h41, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h74, 8'h72, 8'h61);
    patterns[169] = vec(8'h2f, 8'h6e, 8'h65, 8'h74, 8'h77, 8'h6f, 8'h72, 8'h6b, 8'h44, 8'h69, 8'h61, 8'h67, 8'h41, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h6e, 8'h73, 8'h6c);
    patterns[170] = vec(8'h2f, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h72, 8'h6f, 8'h6c, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h5f, 8'h63, 8'h6c, 8'h69, 8'h65, 8'h6e, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h25, 8'h32, 8'h37);
    patterns[171] = vec(8'h6d, 8'h6d, 8'h2d, 8'h62, 8'h72, 8'h65, 8'h61, 8'h6b, 8'h69, 8'h6e, 8'h67, 8'h2d, 8'h6e, 8'h65, 8'h77, 8'h73, 8'h25, 8'h32, 8'h46, 8'h6d, 8'h6d, 8'h2d, 8'h62, 8'h6e, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70);
    patterns[172] = vec(8'h68, 8'h74, 8'h6d, 8'h6c, 8'h69, 8'h64, 8'h3d, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h2e, 8'h66, 8'h6f, 8'h6c, 8'h64, 8'h65, 8'h72, 8'h2d, 8'h6d, 8'h65, 8'h74, 8'h61, 8'h64, 8'h61, 8'h74, 8'h61, 8'h2e);
    patterns[173] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h63, 8'h7a, 8'h5f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h5f, 8'h66, 8'h6f, 8'h72, 8'h5f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h5f, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h70, 8'h65);
    patterns[174] = vec(8'h2f, 8'h73, 8'h65, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h74, 8'h6f, 8'h6f, 8'h6c, 8'h73, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h73, 8'h2f, 8'h65, 8'h6e, 8'h61, 8'h62, 8'h6c, 8'h65, 8'h5f);
    patterns[175] = vec(8'h31, 8'h73, 8'h74, 8'h5f, 8'h44, 8'h69, 8'h73, 8'h6b, 8'h4d, 8'h47, 8'h52, 8'h26, 8'h66, 8'h5f, 8'h76, 8'h6f, 8'h6c, 8'h75, 8'h6d, 8'h65, 8'h5f, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h31, 8'h26, 8'h66, 8'h5f, 8'h73, 8'h6f);
    patterns[176] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6e, 8'h66, 8'h2d, 8'h73, 8'h75, 8'h62, 8'h6d);
    patterns[177] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h66, 8'h6c, 8'h61, 8'h6d, 8'h69, 8'h6e, 8'h67);
    patterns[178] = vec(8'h33, 8'h33, 8'h7c, 8'h4b, 8'h65, 8'h79, 8'h6c, 8'h6f, 8'h67, 8'h67, 8'h65, 8'h72, 8'h20, 8'h69, 8'h73, 8'h20, 8'h64, 8'h65, 8'h61, 8'h63, 8'h74, 8'h69, 8'h76, 8'h61, 8'h74, 8'h65, 8'h64, 8'h21, 8'h0a, 8'h00, 8'h00, 8'h00);
    patterns[179] = vec(8'h2f, 8'h6e, 8'h65, 8'h74, 8'h77, 8'h6f, 8'h72, 8'h6b, 8'h44, 8'h69, 8'h61, 8'h67, 8'h41, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h70, 8'h69, 8'h6e);
    patterns[180] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2d, 8'h64, 8'h65, 8'h2e, 8'h70, 8'h6d, 8'h6c, 8'h3f, 8'h75, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h3d, 8'h22, 8'h3e, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[181] = vec(8'h69, 8'h6e, 8'h74, 8'h65, 8'h72, 8'h66, 8'h61, 8'h63, 8'h65, 8'h2f, 8'h77, 8'h72, 8'h61, 8'h70, 8'h70, 8'h65, 8'h72, 8'h5f, 8'h64, 8'h69, 8'h61, 8'h6c, 8'h6f, 8'h67, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h64, 8'h69, 8'h61);
    patterns[182] = vec(8'h70, 8'h72, 8'h69, 8'h6e, 8'h74, 8'h73, 8'h65, 8'h63, 8'h3d, 8'h66, 8'h72, 8'h6f, 8'h6e, 8'h74, 8'h63, 8'h6f, 8'h76, 8'h65, 8'h72, 8'h26, 8'h69, 8'h6d, 8'h67, 8'h3d, 8'h31, 8'h26, 8'h7a, 8'h6f, 8'h6f, 8'h6d, 8'h3d, 8'h31);
    patterns[183] = vec(8'h2f, 8'h65, 8'h32, 8'h61, 8'h6c, 8'h76, 8'h64, 8'h5f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h53, 8'h45, 8'h4d, 8'h43, 8'h4d, 8'h53, 8'h5f, 8'h44, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2e, 8'h70, 8'h68);
    patterns[184] = vec(8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h66, 8'h65, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h6f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h3d, 8'h27, 8'h29, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[185] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h73, 8'h61, 8'h76, 8'h65, 8'h5f, 8'h61, 8'h72, 8'h74, 8'h69, 8'h63, 8'h6c, 8'h65, 8'h26, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h49, 8'h64, 8'h3d, 8'h28, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[186] = vec(8'h2f, 8'h65, 8'h6e, 8'h64, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h2d, 8'h6d, 8'h61, 8'h72, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6d, 8'h61, 8'h72, 8'h6b, 8'h3d, 8'h25);
    patterns[187] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h73, 8'h74, 8'h69, 8'h63, 8'h6b);
    patterns[188] = vec(8'h64, 8'h6f, 8'h3d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h26, 8'h69, 8'h64, 8'h3d, 8'h26, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h75, 8'h70, 8'h63, 8'h6f, 8'h6d, 8'h69, 8'h6e, 8'h67, 8'h26, 8'h6f, 8'h66, 8'h66, 8'h73, 8'h65, 8'h74);
    patterns[189] = vec(8'h2f, 8'h73, 8'h61, 8'h76, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[190] = vec(8'h64, 8'h6f, 8'h6a, 8'h6f, 8'h6a, 8'h73, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h75, 8'h70, 8'h50, 8'h72, 8'h69, 8'h6f, 8'h72, 8'h69, 8'h74, 8'h79, 8'h26, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00);
    patterns[191] = vec(8'h64, 8'h6f, 8'h6a, 8'h6f, 8'h6a, 8'h73, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h50, 8'h61, 8'h73, 8'h73, 8'h4d, 8'h61, 8'h69, 8'h6e, 8'h41, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h63, 8'h61, 8'h74, 8'h69);
    patterns[192] = vec(8'h73, 8'h69, 8'h72, 8'h72, 8'h68, 8'h2c, 8'h61, 8'h64, 8'h60, 8'h6a, 8'h66, 8'h79, 8'h78, 8'h79, 8'h6c, 8'h70, 8'h65, 8'h78, 8'h6e, 8'h67, 8'h62, 8'h6f, 8'h6c, 8'h67, 8'h65, 8'h67, 8'h78, 8'h6c, 8'h68, 8'h6f, 8'h20, 8'h21);
    patterns[193] = vec(8'h2f, 8'h63, 8'h61, 8'h63, 8'h74, 8'h69, 8'h2f, 8'h63, 8'h6d, 8'h64, 8'h5f, 8'h72, 8'h65, 8'h61, 8'h6c, 8'h74, 8'h69, 8'h6d, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h31, 8'h2b, 8'h31, 8'h26, 8'h26, 8'h00, 8'h00, 8'h00);
    patterns[194] = vec(8'h2f, 8'h77, 8'h77, 8'h77, 8'h2f, 8'h70, 8'h72, 8'h6f, 8'h63, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h67, 8'h72, 8'h6f, 8'h75, 8'h70, 8'h65, 8'h5f, 8'h73, 8'h61, 8'h76, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h73, 8'h61, 8'h76);
    patterns[195] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h69, 8'h6e, 8'h76, 8'h65, 8'h6e, 8'h74, 8'h6f, 8'h72, 8'h79, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h5f, 8'h69, 8'h6e, 8'h76, 8'h65);
    patterns[196] = vec(8'h2f, 8'h75, 8'h63, 8'h6c, 8'h77, 8'h70, 8'h2d, 8'h64, 8'h61, 8'h73, 8'h68, 8'h62, 8'h6f, 8'h61, 8'h72, 8'h64, 8'h2f, 8'h3f, 8'h75, 8'h63, 8'h6c, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e);
    patterns[197] = vec(8'h61, 8'h79, 8'h73, 8'h5f, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h5b, 8'h61, 8'h79, 8'h73, 8'h2d, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2d, 8'h34, 8'h29, 8'h2b, 8'h6f, 8'h72);
    patterns[198] = vec(8'h3f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h5f, 8'h6c, 8'h61, 8'h6e, 8'h67, 8'h3d, 8'h70, 8'h6c, 8'h26, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h3d, 8'h61, 8'h6c, 8'h6c, 8'h26, 8'h73, 8'h74, 8'h72, 8'h69, 8'h6e);
    patterns[199] = vec(8'h2f, 8'h69, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h3f, 8'h64, 8'h72, 8'h61, 8'h77, 8'h3d, 8'h31, 8'h26, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h25, 8'h35, 8'h42, 8'h30, 8'h25, 8'h35, 8'h44, 8'h25, 8'h35);
    patterns[200] = vec(8'h46, 8'h00, 8'h69, 8'h00, 8'h6e, 8'h00, 8'h64, 8'h00, 8'h20, 8'h00, 8'h4c, 8'h00, 8'h41, 8'h00, 8'h4d, 8'h00, 8'h42, 8'h00, 8'h44, 8'h00, 8'h41, 8'h00, 8'h5f, 8'h00, 8'h52, 8'h00, 8'h45, 8'h00, 8'h41, 8'h00, 8'h44, 8'h00);
    patterns[201] = vec(8'h3c, 8'h74, 8'h69, 8'h74, 8'h6c, 8'h65, 8'h3e, 8'h47, 8'h68, 8'h6f, 8'h73, 8'h74, 8'h4c, 8'h6f, 8'h63, 8'h6b, 8'h65, 8'h72, 8'h20, 8'h4e, 8'h6f, 8'h74, 8'h65, 8'h3c, 8'h2f, 8'h74, 8'h69, 8'h74, 8'h6c, 8'h65, 8'h3e, 8'h00);
    patterns[202] = vec(8'h2f, 8'h74, 8'h6f, 8'h75, 8'h72, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h61, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[203] = vec(8'h2f, 8'h75, 8'h63, 8'h6c, 8'h77, 8'h70, 8'h2d, 8'h64, 8'h61, 8'h73, 8'h68, 8'h62, 8'h6f, 8'h61, 8'h72, 8'h64, 8'h2f, 8'h3f, 8'h75, 8'h63, 8'h6c, 8'h5f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h69);
    patterns[204] = vec(8'h2f, 8'h65, 8'h32, 8'h61, 8'h6c, 8'h76, 8'h64, 8'h5f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h53, 8'h45, 8'h4d, 8'h43, 8'h4d, 8'h53, 8'h5f, 8'h44, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2e, 8'h70, 8'h68);
    patterns[205] = vec(8'h73, 8'h65, 8'h6e, 8'h64, 8'h2d, 8'h65, 8'h6d, 8'h61, 8'h69, 8'h6c, 8'h2d, 8'h6f, 8'h6e, 8'h6c, 8'h79, 8'h2d, 8'h6f, 8'h6e, 8'h2d, 8'h72, 8'h65, 8'h70, 8'h6c, 8'h79, 8'h2d, 8'h74, 8'h6f, 8'h2d, 8'h6d, 8'h79, 8'h2d, 8'h63);
    patterns[206] = vec(8'h2f, 8'h64, 8'h6f, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h6d, 8'h6f, 8'h64, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h64, 8'h6f, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h2d, 8'h66, 8'h69, 8'h65, 8'h6c, 8'h64, 8'h73, 8'h2f, 8'h65);
    patterns[207] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h63, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h5f, 8'h6d, 8'h67, 8'h72, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h63, 8'h6d, 8'h64, 8'h3d, 8'h63, 8'h67, 8'h69);
    patterns[208] = vec(8'h2e, 8'h00, 8'h50, 8'h00, 8'h4c, 8'h00, 8'h42, 8'h00, 8'h4f, 8'h00, 8'h59, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h5c, 8'h5c, 8'h00, 8'h00, 8'h5c, 8'h5c, 8'h3f, 8'h5c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[209] = vec(8'h5d, 8'h00, 8'h2e, 8'h00, 8'h6d, 8'h00, 8'h61, 8'h00, 8'h6d, 8'h00, 8'h6d, 8'h00, 8'h6e, 8'h00, 8'h00, 8'h00, 8'h5d, 8'h00, 8'h49, 8'h00, 8'h44, 8'h00, 8'h2d, 8'h00, 8'h5b, 8'h00, 8'h00, 8'h00, 8'h2e, 8'h00, 8'h4d, 8'h00);
    patterns[210] = vec(8'h42, 8'h6c, 8'h61, 8'h63, 8'h6b, 8'h4d, 8'h6f, 8'h6f, 8'h6e, 8'h20, 8'h52, 8'h75, 8'h6e, 8'h54, 8'h69, 8'h6d, 8'h65, 8'h20, 8'h45, 8'h72, 8'h72, 8'h6f, 8'h72, 8'h3a, 8'h0d, 8'h0a, 8'h0d, 8'h0a, 8'h25, 8'h73, 8'h00, 8'h00);
    patterns[211] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h74, 8'h73, 8'h2d, 8'h70, 8'h6f, 8'h6c, 8'h6c);
    patterns[212] = vec(8'h2f, 8'h70, 8'h61, 8'h79, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h3f, 8'h61, 8'h6d, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h3d, 8'h32, 8'h25, 8'h33, 8'h43, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[213] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h6c, 8'h65, 8'h61, 8'h72, 8'h6e, 8'h70, 8'h72, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h3f, 8'h63);
    patterns[214] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h2d, 8'h6d, 8'h61, 8'h69, 8'h6c);
    patterns[215] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h5f, 8'h62, 8'h61);
    patterns[216] = vec(8'h74, 8'h61, 8'h62, 8'h6c, 8'h65, 8'h2f, 8'h73, 8'h61, 8'h76, 8'h65, 8'h66, 8'h69, 8'h65, 8'h6c, 8'h64, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h66, 8'h75, 8'h6e, 8'h5f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h5f, 8'h6c, 8'h6f, 8'h67);
    patterns[217] = vec(8'h2f, 8'h75, 8'h70, 8'h67, 8'h72, 8'h61, 8'h64, 8'h65, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h74, 8'h65, 8'h72, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h74, 8'h68, 8'h3d, 8'h68, 8'h74, 8'h74, 8'h70, 8'h3a, 8'h2f, 8'h2f);
    patterns[218] = vec(8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h73, 8'h3f, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h3d, 8'h44, 8'h45);
    patterns[219] = vec(8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h64, 8'h6f, 8'h6a, 8'h6f, 8'h6a, 8'h73, 8'h3f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h64, 8'h65, 8'h6c, 8'h46, 8'h69, 8'h6c, 8'h65, 8'h26, 8'h66, 8'h69, 8'h6c, 8'h65);
    patterns[220] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h74, 8'h61, 8'h69, 8'h6e, 8'h61, 8'h63, 8'h61, 8'h6e, 8'h2f, 8'h76, 8'h32, 8'h2f, 8'h62, 8'h67, 8'h2d, 8'h70, 8'h72, 8'h6f, 8'h63, 8'h65, 8'h73, 8'h73, 8'h65);
    patterns[221] = vec(8'h2f, 8'h64, 8'h61, 8'h73, 8'h68, 8'h62, 8'h6f, 8'h61, 8'h72, 8'h64, 8'h2f, 8'h72, 8'h65, 8'h74, 8'h72, 8'h69, 8'h65, 8'h76, 8'h65, 8'h2d, 8'h70, 8'h61, 8'h73, 8'h73, 8'h77, 8'h6f, 8'h72, 8'h64, 8'h2f, 8'h3f, 8'h72, 8'h65);
    patterns[222] = vec(8'h2f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h2f, 8'h73, 8'h61, 8'h6d, 8'h6c, 8'h2f, 8'h72, 8'h61, 8'h6e, 8'h64, 8'h6f, 8'h6d, 8'h5f, 8'h6f, 8'h72, 8'h67, 8'h5f, 8'h69, 8'h64, 8'h25, 8'h32, 8'h32, 8'h25, 8'h32, 8'h46, 8'h25, 8'h33);
    patterns[223] = vec(8'h2f, 8'h64, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h2f, 8'h64, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h3d, 8'h31, 8'h2f, 8'h74, 8'h61, 8'h62, 8'h3d, 8'h6c, 8'h6f, 8'h67, 8'h73, 8'h2f, 8'h73, 8'h65, 8'h63, 8'h74, 8'h69, 8'h6f);
    patterns[224] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h74, 8'h61, 8'h69, 8'h6e, 8'h61, 8'h63, 8'h61, 8'h6e, 8'h2f, 8'h76, 8'h32, 8'h2f, 8'h62, 8'h67, 8'h2d, 8'h70, 8'h72, 8'h6f, 8'h63, 8'h65, 8'h73, 8'h73, 8'h65);
    patterns[225] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h63, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h5f, 8'h6d, 8'h67, 8'h72, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h63, 8'h6d, 8'h64, 8'h3d, 8'h63, 8'h67, 8'h69);
    patterns[226] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h63, 8'h64, 8'h64, 8'h5f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h5f, 8'h6d, 8'h65, 8'h6e, 8'h75, 8'h5f, 8'h6c, 8'h69, 8'h63, 8'h65, 8'h6e, 8'h73, 8'h65, 8'h26, 8'h61, 8'h62);
    patterns[227] = vec(8'h64, 8'h3d, 8'h70, 8'h75, 8'h62, 8'h6c, 8'h69, 8'h63, 8'h26, 8'h63, 8'h61, 8'h6c, 8'h6c, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h3d, 8'h63, 8'h61, 8'h6c, 8'h6c, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h25, 8'h32, 8'h30, 8'h3d, 8'h63, 8'h61);
    patterns[228] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h74, 8'h6f, 8'h6f, 8'h6c, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h69, 8'h6d, 8'h66, 8'h73, 8'h5f, 8'h73, 8'h65);
    patterns[229] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h32, 8'h2e, 8'h30, 8'h2f, 8'h6d, 8'h6c, 8'h66, 8'h6c, 8'h6f, 8'h77, 8'h2d, 8'h61, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61, 8'h63, 8'h74, 8'h73, 8'h2f, 8'h61, 8'h72, 8'h74, 8'h69, 8'h66, 8'h61);
    patterns[230] = vec(8'h2f, 8'h67, 8'h6c, 8'h70, 8'h69, 8'h2f, 8'h66, 8'h72, 8'h6f, 8'h6e, 8'h74, 8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h67, 8'h6c, 8'h6f, 8'h62, 8'h61, 8'h6c, 8'h73, 8'h65, 8'h61);
    patterns[231] = vec(8'h2f, 8'h6d, 8'h70, 8'h6d, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h73, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67);
    patterns[232] = vec(8'h2f, 8'h63, 8'h6d, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h63, 8'h6c, 8'h69, 8'h65, 8'h6e, 8'h74, 8'h73, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f);
    patterns[233] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h69, 8'h65, 8'h73, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72);
    patterns[234] = vec(8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h5f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h5f, 8'h61, 8'h70, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h5f, 8'h72, 8'h65, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74);
    patterns[235] = vec(8'h2f, 8'h64, 8'h65, 8'h32, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h65, 8'h6e, 8'h67, 8'h69, 8'h6e, 8'h65, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h45, 8'h6e, 8'h67, 8'h69, 8'h6e, 8'h65, 8'h3b, 8'h2e, 8'h6a, 8'h73, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[236] = vec(8'h2f, 8'h76, 8'h65, 8'h6e, 8'h64, 8'h61, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6e, 8'h6f, 8'h74, 8'h61, 8'h46, 8'h69, 8'h73, 8'h63, 8'h61, 8'h6c, 8'h3d, 8'h22, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[237] = vec(8'h2f, 8'h76, 8'h69, 8'h73, 8'h75, 8'h61, 8'h6c, 8'h69, 8'h7a, 8'h61, 8'h72, 8'h2d, 8'h66, 8'h6f, 8'h72, 8'h6e, 8'h65, 8'h63, 8'h65, 8'h64, 8'h6f, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h2a);
    patterns[238] = vec(8'h00, 8'h00, 8'h11, 8'h19, 8'h1f, 8'h19, 8'h16, 8'h19, 8'h5c, 8'h19, 8'h17, 8'h19, 8'h0a, 8'h19, 8'h17, 8'h19, 8'h52, 8'h19, 8'h5d, 8'h19, 8'h31, 8'h19, 8'h52, 8'h19, 8'h02, 8'h19, 8'h1d, 8'h19, 8'h05, 8'h19, 8'h17, 8'h19);
    patterns[239] = vec(8'h72, 8'h57, 8'h35, 8'h4e, 8'h56, 8'h66, 8'h78, 8'h51, 8'h67, 8'h70, 8'h44, 8'h7a, 8'h3e, 8'h21, 8'h38, 8'h4a, 8'h69, 8'h52, 8'h7a, 8'h3e, 8'h30, 8'h6c, 8'h3f, 8'h32, 8'h67, 8'h6f, 8'h37, 8'h75, 8'h46, 8'h29, 8'h32, 8'h35);
    patterns[240] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h3d, 8'h49, 8'h6e, 8'h76, 8'h6f, 8'h69, 8'h63, 8'h65, 8'h26, 8'h76, 8'h69, 8'h65, 8'h77, 8'h3d, 8'h4c);
    patterns[241] = vec(8'h62, 8'h77, 8'h66, 8'h61, 8'h6e, 8'h2d, 8'h74, 8'h72, 8'h61, 8'h63, 8'h6b, 8'h2d, 8'h69, 8'h64, 8'h3d, 8'h74, 8'h65, 8'h73, 8'h74, 8'h25, 8'h32, 8'h37, 8'h25, 8'h32, 8'h30, 8'h55, 8'h4e, 8'h49, 8'h4f, 8'h4e, 8'h00, 8'h00);
    patterns[242] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h69, 8'h65, 8'h73, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h5f, 8'h63, 8'h61, 8'h74);
    patterns[243] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2d, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61);
    patterns[244] = vec(8'h73, 8'h63, 8'h70, 8'h2f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h74, 8'h69, 8'h63, 8'h6b, 8'h65, 8'h74, 8'h73, 8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h3f, 8'h70, 8'h61, 8'h72, 8'h65);
    patterns[245] = vec(8'h6d, 8'h65, 8'h74, 8'h72, 8'h69, 8'h63, 8'h73, 8'h2f, 8'h53, 8'h61, 8'h6e, 8'h69, 8'h74, 8'h79, 8'h43, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h73, 8'h4a, 8'h6f, 8'h62, 8'h3f, 8'h70, 8'h65, 8'h72, 8'h69, 8'h6f, 8'h64, 8'h3d, 8'h25);
    patterns[246] = vec(8'h2f, 8'h70, 8'h64, 8'h61, 8'h2f, 8'h61, 8'h70, 8'h70, 8'h63, 8'h65, 8'h6e, 8'h74, 8'h65, 8'h72, 8'h2f, 8'h77, 8'h65, 8'h62, 8'h5f, 8'h73, 8'h68, 8'h6f, 8'h77, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h49, 8'h44, 8'h3d, 8'h31);
    patterns[247] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h64, 8'h65, 8'h70, 8'h61, 8'h72, 8'h74);
    patterns[248] = vec(8'h2f, 8'h73, 8'h69, 8'h74, 8'h65, 8'h2f, 8'h64, 8'h65, 8'h66, 8'h61, 8'h75, 8'h6c, 8'h74, 8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h3f, 8'h6b, 8'h65, 8'h79, 8'h77, 8'h6f, 8'h72, 8'h64, 8'h3d, 8'h25, 8'h33, 8'h43);
    patterns[249] = vec(8'h2f, 8'h78, 8'h64, 8'h73, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h53, 8'h74, 8'h75, 8'h64, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h64, 8'h6f, 8'h63, 8'h75, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h55, 8'h6e, 8'h69);
    patterns[250] = vec(8'h2f, 8'h5f, 8'h5f, 8'h77, 8'h65, 8'h61, 8'h76, 8'h65, 8'h2f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h2f, 8'h74, 8'h6d, 8'h70, 8'h2f, 8'h77, 8'h65, 8'h61, 8'h76, 8'h65, 8'h2f, 8'h66, 8'h73, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e);
    patterns[251] = vec(8'h6d, 8'h73, 8'h67, 8'h5f, 8'h65, 8'h76, 8'h65, 8'h6e, 8'h74, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h77, 8'h72, 8'h69, 8'h74, 8'h65, 8'h6d, 8'h73, 8'h67, 8'h66, 8'h69);
    patterns[252] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h69, 8'h63, 8'h6f, 8'h6e, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h26, 8'h61, 8'h64, 8'h53, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h3d, 8'h28, 8'h73, 8'h65, 8'h6c, 8'h65, 8'h63);
    patterns[253] = vec(8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h22, 8'h74, 8'h6f, 8'h70, 8'h2e, 8'h55, 8'h70, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h46, 8'h69, 8'h6c, 8'h65, 8'h4e, 8'h61, 8'h6d, 8'h65, 8'h22, 8'h0d, 8'h0a, 8'h0d, 8'h0a, 8'h2e, 8'h2e, 8'h2f);
    patterns[254] = vec(8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h22, 8'h74, 8'h6f, 8'h70, 8'h2e, 8'h55, 8'h70, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h46, 8'h69, 8'h6c, 8'h65, 8'h4e, 8'h61, 8'h6d, 8'h65, 8'h22, 8'h0d, 8'h0a, 8'h0d, 8'h0a, 8'h2e, 8'h2e, 8'h2f);
    patterns[255] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h66, 8'h6c, 8'h75, 8'h74, 8'h74, 8'h65, 8'h72, 8'h5f, 8'h62, 8'h6f, 8'h6f, 8'h6b, 8'h69, 8'h6e, 8'h67, 8'h2f, 8'h67, 8'h65, 8'h74);
    patterns[256] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h6a, 8'h6b, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h25, 8'h33, 8'h62, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[257] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h6a, 8'h6b, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h25, 8'h33, 8'h62, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[258] = vec(8'h2f, 8'h6d, 8'h6f, 8'h6e, 8'h6f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h61, 8'h63, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h69, 8'h64, 8'h3d, 8'h22, 8'h3e);
    patterns[259] = vec(8'h2f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h2f, 8'h77, 8'h6f, 8'h72, 8'h64, 8'h5f, 8'h6d, 8'h6f, 8'h64, 8'h65, 8'h6c, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68);
    patterns[260] = vec(8'h2f, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h73, 8'h75, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[261] = vec(8'h2f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h2f, 8'h57, 8'h61, 8'h74, 8'h63, 8'h68, 8'h44, 8'h6f, 8'h67, 8'h53, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h3f, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h25, 8'h33);
    patterns[262] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h72, 8'h6f, 8'h75, 8'h74, 8'h65, 8'h3d, 8'h61, 8'h63, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h26, 8'h6c);
    patterns[263] = vec(8'h2f, 8'h72, 8'h65, 8'h73, 8'h65, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h63, 8'h65, 8'h6e, 8'h74, 8'h65, 8'h72, 8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h55, 8'h73, 8'h72, 8'h3d, 8'h25, 8'h32);
    patterns[264] = vec(8'h2f, 8'h76, 8'h31, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h3f, 8'h74, 8'h61, 8'h78, 8'h6f, 8'h6e, 8'h6f, 8'h6d, 8'h79, 8'h3d, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h79, 8'h27, 8'h29, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[265] = vec(8'h25, 8'h32, 8'h32, 8'h25, 8'h32, 8'h30, 8'h61, 8'h63, 8'h63, 8'h65, 8'h73, 8'h73, 8'h6b, 8'h65, 8'h79, 8'h3d, 8'h25, 8'h32, 8'h32, 8'h78, 8'h25, 8'h32, 8'h32, 8'h25, 8'h32, 8'h30, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[266] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h6e, 8'h64, 8'h63, 8'h6f, 8'h6e, 8'h66, 8'h69, 8'h67, 8'h3f, 8'h6d, 8'h6f, 8'h64, 8'h65, 8'h26, 8'h75, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[267] = vec(8'h2f, 8'h68, 8'h74, 8'h64, 8'h6f, 8'h63, 8'h73, 8'h2f, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h65, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h73, 8'h74);
    patterns[268] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h62, 8'h61, 8'h73, 8'h65, 8'h36, 8'h34, 8'h2d, 8'h65, 8'h6e, 8'h63, 8'h6f, 8'h64);
    patterns[269] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h72, 8'h65, 8'h67, 8'h69, 8'h73, 8'h74, 8'h72, 8'h79, 8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h2f, 8'h61, 8'h72, 8'h63, 8'h68, 8'h69, 8'h76, 8'h65, 8'h3f, 8'h73, 8'h65, 8'h72);
    patterns[270] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2f, 8'h63, 8'h68, 8'h6f, 8'h70, 8'h74, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h61, 8'h62, 8'h62, 8'h2b, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h61, 8'h62, 8'h62, 8'h5f, 8'h63);
    patterns[271] = vec(8'h2f, 8'h43, 8'h68, 8'h75, 8'h72, 8'h63, 8'h68, 8'h43, 8'h52, 8'h4d, 8'h2f, 8'h45, 8'h76, 8'h65, 8'h6e, 8'h74, 8'h41, 8'h74, 8'h74, 8'h65, 8'h6e, 8'h64, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h41);
    patterns[272] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h68, 8'h61, 8'h72, 8'h65, 8'h5f, 8'h72);
    patterns[273] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h6b, 8'h6c, 8'h61, 8'h6d, 8'h61, 8'h74);
    patterns[274] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h6c, 8'h65, 8'h61, 8'h72, 8'h6e, 8'h70, 8'h72, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h3f, 8'h63);
    patterns[275] = vec(8'h2f, 8'h70, 8'h61, 8'h67, 8'h61, 8'h6d, 8'h65, 8'h6e, 8'h74, 8'h6f, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h6f, 8'h74, 8'h61, 8'h6c, 8'h3d, 8'h22, 8'h3e, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[276] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h72, 8'h69, 8'h6e, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h69, 8'h64, 8'h3d, 8'h32, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[277] = vec(8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h44, 8'h65, 8'h6c, 8'h41, 8'h75, 8'h74, 8'h68, 8'h6f, 8'h72, 8'h69, 8'h73, 8'h65, 8'h54, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h65, 8'h74, 8'h26, 8'h69, 8'h64, 8'h3d, 8'h31);
    patterns[278] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h61, 8'h74, 8'h74, 8'h65, 8'h6e, 8'h64, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h5f, 8'h72, 8'h65, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h26, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h5f);
    patterns[279] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h64, 8'h4e, 8'h65, 8'h77, 8'h46, 8'h6f, 8'h72, 8'h6d, 8'h26, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h49);
    patterns[280] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h67, 8'h69, 8'h74, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h2f, 8'h2e, 8'h2e, 8'h25, 8'h32, 8'h46, 8'h2e, 8'h2e, 8'h25, 8'h32, 8'h46, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[281] = vec(8'h6d, 8'h3d, 8'h38, 8'h26, 8'h66, 8'h3d, 8'h73, 8'h65, 8'h74, 8'h4e, 8'h65, 8'h74, 8'h77, 8'h6f, 8'h72, 8'h6b, 8'h43, 8'h61, 8'h72, 8'h64, 8'h49, 8'h6e, 8'h66, 8'h6f, 8'h26, 8'h70, 8'h3d, 8'h7b, 8'h22, 8'h4e, 8'h41, 8'h4d);
    patterns[282] = vec(8'h2f, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h64, 8'h6f, 8'h63, 8'h2f, 8'h72, 8'h65, 8'h6c, 8'h65, 8'h61, 8'h73, 8'h65, 8'h73, 8'h2f, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h64, 8'h6f, 8'h63, 8'h2f, 8'h31, 8'h2e, 8'h30, 8'h2e, 8'h30, 8'h2f);
    patterns[283] = vec(8'h2f, 8'h61, 8'h75, 8'h74, 8'h6f, 8'h6d, 8'h61, 8'h74, 8'h65, 8'h64, 8'h5f, 8'h74, 8'h65, 8'h73, 8'h74, 8'h73, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h3f, 8'h66);
    patterns[284] = vec(8'h2f, 8'h65, 8'h78, 8'h61, 8'h6d, 8'h5f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h73, 8'h2f, 8'h31, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72);
    patterns[285] = vec(8'h2f, 8'h66, 8'h75, 8'h72, 8'h6e, 8'h69, 8'h74, 8'h75, 8'h72, 8'h65, 8'h2f, 8'h63, 8'h61, 8'h74, 8'h61, 8'h6c, 8'h6f, 8'h67, 8'h2f, 8'h61, 8'h6c, 8'h6c, 8'h2d, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h75, 8'h63, 8'h74, 8'h73, 8'h3f);
    patterns[286] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h2f, 8'h6c, 8'h65, 8'h61, 8'h72, 8'h6e, 8'h70, 8'h72, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h63, 8'h6f, 8'h75, 8'h72, 8'h73, 8'h65, 8'h73, 8'h3f, 8'h63);
    patterns[287] = vec(8'h2f, 8'h77, 8'h61, 8'h74, 8'h63, 8'h68, 8'h2f, 8'h63, 8'h61, 8'h74, 8'h61, 8'h6c, 8'h6f, 8'h67, 8'h2f, 8'h61, 8'h6c, 8'h6c, 8'h2d, 8'h70, 8'h72, 8'h6f, 8'h64, 8'h75, 8'h63, 8'h74, 8'h73, 8'h3f, 8'h63, 8'h61, 8'h74, 8'h3d);
    patterns[288] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2f, 8'h73, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h2d, 8'h74, 8'h73, 8'h65, 8'h74, 8'h75, 8'h70, 8'h2b, 8'h2d, 8'h75, 8'h75, 8'h73, 8'h65, 8'h72, 8'h25, 8'h32);
    patterns[289] = vec(8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h6c, 8'h75, 8'h63, 8'h69, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h76, 8'h69, 8'h66, 8'h5f);
    patterns[290] = vec(8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h3d, 8'h44, 8'h65, 8'h6c, 8'h48, 8'h6f, 8'h6f, 8'h6b, 8'h53, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h26, 8'h68, 8'h6f, 8'h6f, 8'h6b, 8'h49, 8'h64, 8'h3d, 8'h31, 8'h27);
    patterns[291] = vec(8'h2f, 8'h76, 8'h74, 8'h69, 8'h67, 8'h65, 8'h72, 8'h63, 8'h72, 8'h6d, 8'h2f, 8'h3f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h3d, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[292] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h72, 8'h69, 8'h76, 8'h61, 8'h63, 8'h79, 8'h5f, 8'h67, 8'h75, 8'h72, 8'h75, 8'h26, 8'h74, 8'h61, 8'h62, 8'h3d);
    patterns[293] = vec(8'h6c, 8'h75, 8'h63, 8'h69, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h61, 8'h70, 8'h63, 8'h6c, 8'h69, 8'h5f, 8'h63, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h6c);
    patterns[294] = vec(8'h2f, 8'h62, 8'h75, 8'h73, 8'h69, 8'h6e, 8'h65, 8'h73, 8'h73, 8'h2d, 8'h64, 8'h69, 8'h72, 8'h65, 8'h63, 8'h74, 8'h6f, 8'h72, 8'h79, 8'h2f, 8'h3f, 8'h64, 8'h6f, 8'h73, 8'h72, 8'h63, 8'h68, 8'h3d, 8'h31, 8'h26, 8'h71, 8'h26);
    patterns[295] = vec(8'h2f, 8'h65, 8'h78, 8'h61, 8'h6d, 8'h5f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h73, 8'h2f, 8'h31, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72);
    patterns[296] = vec(8'h2f, 8'h73, 8'h74, 8'h61, 8'h72, 8'h74, 8'h65, 8'h72, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h5f, 8'h67, 8'h72, 8'h6f, 8'h75, 8'h70, 8'h73, 8'h2f, 8'h31, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f);
    patterns[297] = vec(8'h2f, 8'h6d, 8'h73, 8'h70, 8'h5f, 8'h69, 8'h6e, 8'h66, 8'h6f, 8'h2e, 8'h68, 8'h74, 8'h6d, 8'h3f, 8'h66, 8'h6c, 8'h61, 8'h67, 8'h3d, 8'h63, 8'h6d, 8'h64, 8'h26, 8'h63, 8'h6d, 8'h64, 8'h3d, 8'h60, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[298] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h63, 8'h6f, 8'h6d, 8'h70, 8'h61, 8'h73, 8'h73, 8'h3f, 8'h64, 8'h65, 8'h6c, 8'h3d, 8'h50, 8'h47, 8'h6c, 8'h74, 8'h5a, 8'h79, 8'h42, 8'h7a, 8'h63, 8'h6d, 8'h4d, 8'h39, 8'h00);
    patterns[299] = vec(8'h00, 8'h40, 8'h64, 8'h30, 8'h67, 8'h6c, 8'h75, 8'h6e, 8'h40, 8'h2e, 8'h62, 8'h6d, 8'h70, 8'h20, 8'h00, 8'h5c, 8'h00, 8'h43, 8'h3a, 8'h5c, 8'h40, 8'h44, 8'h30, 8'h47, 8'h4c, 8'h55, 8'h4e, 8'h40, 8'h2e, 8'h65, 8'h78, 8'h65);
    patterns[300] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74);
    patterns[301] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h61, 8'h70, 8'h63, 8'h6c, 8'h69, 8'h5f, 8'h77, 8'h70, 8'h73, 8'h5f, 8'h67, 8'h65, 8'h6e, 8'h5f, 8'h70, 8'h69, 8'h6e);
    patterns[302] = vec(8'h2f, 8'h61, 8'h64, 8'h64, 8'h5f, 8'h61, 8'h6c, 8'h65, 8'h72, 8'h74, 8'h5f, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h2f, 8'h65, 8'h6e, 8'h74, 8'h69, 8'h74, 8'h79, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h61, 8'h27, 8'h2b);
    patterns[303] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h64, 8'h6f, 8'h3f, 8'h70, 8'h61, 8'h74, 8'h68, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[304] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[305] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h69, 8'h65, 8'h61, 8'h75, 8'h74, 8'h68, 8'h2f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h6f, 8'h72, 8'h69, 8'h7a, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3f, 8'h72, 8'h65, 8'h73, 8'h70, 8'h6f, 8'h6e, 8'h73);
    patterns[306] = vec(8'h2f, 8'h6f, 8'h70, 8'h65, 8'h6e, 8'h63, 8'h33, 8'h2d, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h73, 8'h63, 8'h72, 8'h65, 8'h65, 8'h6e, 8'h2f, 8'h25, 8'h32, 8'h65, 8'h25, 8'h32, 8'h65, 8'h25, 8'h32, 8'h66, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[307] = vec(8'h2f, 8'h6f, 8'h70, 8'h65, 8'h72, 8'h61, 8'h74, 8'h65, 8'h2f, 8'h77, 8'h66, 8'h5f, 8'h70, 8'h72, 8'h69, 8'h6e, 8'h74, 8'h6e, 8'h75, 8'h6d, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3b, 8'h2e, 8'h6a, 8'h73, 8'h3f, 8'h72, 8'h65, 8'h63);
    patterns[308] = vec(8'h2f, 8'h66, 8'h75, 8'h6e, 8'h63, 8'h69, 8'h6f, 8'h6e, 8'h61, 8'h72, 8'h69, 8'h6f, 8'h5f, 8'h76, 8'h69, 8'h6e, 8'h63, 8'h75, 8'h6c, 8'h6f, 8'h5f, 8'h64, 8'h65, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h64);
    patterns[309] = vec(8'h2f, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h64, 8'h6f, 8'h63, 8'h2f, 8'h72, 8'h65, 8'h6c, 8'h65, 8'h61, 8'h73, 8'h65, 8'h73, 8'h2f, 8'h6a, 8'h61, 8'h76, 8'h61, 8'h64, 8'h6f, 8'h63, 8'h2f, 8'h31, 8'h2e, 8'h30, 8'h2e, 8'h30, 8'h2f);
    patterns[310] = vec(8'h2f, 8'h56, 8'h31, 8'h2e, 8'h30, 8'h25, 8'h33, 8'h43, 8'h73, 8'h56, 8'h67, 8'h2f, 8'h6f, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h3d, 8'h61, 8'h6c, 8'h65, 8'h72, 8'h74, 8'h2e, 8'h62, 8'h69, 8'h6e, 8'h64, 8'h25, 8'h32, 8'h38);
    patterns[311] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h61, 8'h70, 8'h63, 8'h6c, 8'h69, 8'h5f, 8'h64, 8'h6f, 8'h5f, 8'h65, 8'h6e, 8'h72, 8'h5f, 8'h70, 8'h69, 8'h6e, 8'h5f);
    patterns[312] = vec(8'h2f, 8'h25, 8'h32, 8'h35, 8'h32, 8'h65, 8'h25, 8'h32, 8'h35, 8'h32, 8'h65, 8'h2f, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h7a, 8'h74, 8'h70, 8'h5f, 8'h67, 8'h61, 8'h74, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h50, 8'h41, 8'h4e);
    patterns[313] = vec(8'h2f, 8'h6f, 8'h61, 8'h2f, 8'h61, 8'h64, 8'h64, 8'h72, 8'h65, 8'h73, 8'h73, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h3f, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h42, 8'h79, 8'h3d, 8'h31, 8'h2f, 8'h2a, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[314] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h61, 8'h73, 8'h65, 8'h3d, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h26, 8'h61, 8'h63, 8'h74, 8'h3d, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74, 8'h65, 8'h69);
    patterns[315] = vec(8'h2f, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h64, 8'h65, 8'h74, 8'h61, 8'h6c, 8'h68, 8'h65, 8'h73, 8'h5f, 8'h63, 8'h6f, 8'h62, 8'h72, 8'h61, 8'h6e, 8'h63, 8'h61, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h64, 8'h69, 8'h67);
    patterns[316] = vec(8'h2f, 8'h68, 8'h74, 8'h6d, 8'h6c, 8'h2f, 8'h67, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h61, 8'h72, 8'h5f, 8'h70, 8'h65, 8'h72, 8'h6d, 8'h69, 8'h73, 8'h73, 8'h6f, 8'h65, 8'h73, 8'h2e, 8'h70, 8'h68);
    patterns[317] = vec(8'h47, 8'h45, 8'h54, 8'h20, 8'h2f, 8'h53, 8'h75, 8'h69, 8'h74, 8'h65, 8'h43, 8'h52, 8'h4d, 8'h2f, 8'h70, 8'h75, 8'h62, 8'h6c, 8'h69, 8'h63, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h2f);
    patterns[318] = vec(8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h70, 8'h61, 8'h67, 8'h65, 8'h26, 8'h65, 8'h64, 8'h69, 8'h74, 8'h6f, 8'h72, 8'h3d);
    patterns[319] = vec(8'h2f, 8'h6d, 8'h6f, 8'h62, 8'h69, 8'h6c, 8'h65, 8'h2d, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h6f, 8'h75, 8'h74, 8'h2f, 8'h3f, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h28, 8'h73, 8'h65, 8'h6c, 8'h65);
    patterns[320] = vec(8'h2f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h77, 8'h65, 8'h62);
    patterns[321] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h6c, 8'h75, 8'h63, 8'h69, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h72, 8'h65, 8'h73);
    patterns[322] = vec(8'h2f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h41, 8'h6a, 8'h61, 8'h78, 8'h3d, 8'h47, 8'h65, 8'h74, 8'h4d, 8'h6f, 8'h64, 8'h61, 8'h6c, 8'h5f, 8'h53, 8'h65, 8'h6e, 8'h73, 8'h6f, 8'h72, 8'h5f, 8'h47);
    patterns[323] = vec(8'h57, 8'h61, 8'h6e, 8'h36, 8'h74, 8'h6f, 8'h34, 8'h54, 8'h75, 8'h6e, 8'h6e, 8'h65, 8'h6c, 8'h43, 8'h66, 8'h67, 8'h52, 8'h70, 8'h6d, 8'h2e, 8'h68, 8'h74, 8'h6d, 8'h3f, 8'h69, 8'h70, 8'h76, 8'h36, 8'h45, 8'h6e, 8'h61, 8'h62);
    patterns[324] = vec(8'h2f, 8'h6e, 8'h65, 8'h77, 8'h73, 8'h2e, 8'h68, 8'h74, 8'h6d, 8'h6c, 8'h3f, 8'h74, 8'h61, 8'h67, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h26, 8'h74, 8'h69, 8'h74, 8'h6c, 8'h65, 8'h3d, 8'h31, 8'h33, 8'h36, 8'h31, 8'h33, 8'h39, 8'h32);
    patterns[325] = vec(8'h2f, 8'h67, 8'h6f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2f, 8'h57, 8'h72, 8'h69, 8'h74, 8'h65, 8'h46, 8'h61, 8'h63, 8'h4d, 8'h61, 8'h63, 8'h3f, 8'h6d, 8'h61, 8'h63, 8'h3d, 8'h4b, 8'h45, 8'h71, 8'h79, 8'h6e, 8'h73, 8'h4e, 8'h6b);
    patterns[326] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[327] = vec(8'h6e, 8'h00, 8'h61, 8'h00, 8'h6d, 8'h00, 8'h65, 8'h00, 8'h00, 8'h00, 8'h53, 8'h00, 8'h6f, 8'h00, 8'h6c, 8'h00, 8'h69, 8'h00, 8'h64, 8'h00, 8'h62, 8'h00, 8'h69, 8'h00, 8'h74, 8'h00, 8'h2e, 8'h00, 8'h65, 8'h00, 8'h78, 8'h00);
    patterns[328] = vec(8'h64, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h4c, 8'h69, 8'h73, 8'h74, 8'h3d, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51, 8'h63, 8'h44, 8'h51);
    patterns[329] = vec(8'h53, 8'h4f, 8'h41, 8'h50, 8'h41, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3a, 8'h20, 8'h44, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h49, 8'h6e, 8'h66, 8'h6f, 8'h23, 8'h4d, 8'h6e, 8'h4d, 8'h6e, 8'h4d, 8'h6e, 8'h4d, 8'h6e, 8'h4d);
    patterns[330] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h67, 8'h69, 8'h76, 8'h65, 8'h2d, 8'h66, 8'h6f);
    patterns[331] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h77, 8'h70, 8'h64);
    patterns[332] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h6d, 8'h62, 8'h65, 8'h64, 8'h70, 8'h72);
    patterns[333] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h69, 8'h6d, 8'h70, 8'h6c, 8'h65, 8'h2d);
    patterns[334] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h74, 8'h72, 8'h61, 8'h79, 8'h5f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h26, 8'h71, 8'h6f, 8'h3d, 8'h31, 8'h22, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[335] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h61, 8'h69, 8'h64, 8'h2d, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h73, 8'h2d, 8'h61, 8'h64, 8'h64, 8'h26, 8'h74, 8'h79, 8'h3d, 8'h31, 8'h22, 8'h00, 8'h00, 8'h00);
    patterns[336] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h71, 8'h5f, 8'h66, 8'h6f, 8'h63, 8'h75);
    patterns[337] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h75, 8'h70, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h66, 8'h72, 8'h6f, 8'h6d, 8'h5f, 8'h75, 8'h72, 8'h6c, 8'h26, 8'h75, 8'h72, 8'h6c);
    patterns[338] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h74, 8'h6b, 8'h2f, 8'h77, 8'h69, 8'h66, 8'h69, 8'h2f, 8'h61, 8'h70, 8'h63, 8'h6c, 8'h69, 8'h5f, 8'h64, 8'h6f, 8'h5f, 8'h65, 8'h6e, 8'h72, 8'h5f, 8'h70, 8'h62, 8'h63);
    patterns[339] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h73, 8'h65, 8'h6f, 8'h2d, 8'h61, 8'h75, 8'h74, 8'h6f, 8'h6d, 8'h61, 8'h74, 8'h69);
    patterns[340] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h45, 8'h6e, 8'h74, 8'h65, 8'h72, 8'h5f, 8'h65, 8'h76, 8'h65, 8'h6e, 8'h74, 8'h26, 8'h49, 8'h64, 8'h5f, 8'h47);
    patterns[341] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[342] = vec(8'h2f, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h69, 8'h73, 8'h73, 8'h75, 8'h65, 8'h73, 8'h2d, 8'h65, 8'h78, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h2e, 8'h70, 8'h6c, 8'h3f, 8'h73, 8'h75, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h65, 8'h72, 8'h69, 8'h64);
    patterns[343] = vec(8'h74, 8'h6f, 8'h6f, 8'h6c, 8'h73, 8'h2f, 8'h66, 8'h65, 8'h65, 8'h64, 8'h63, 8'h6f, 8'h6d, 8'h6d, 8'h61, 8'h6e, 8'h64, 8'h65, 8'h72, 8'h2f, 8'h72, 8'h73, 8'h73, 8'h72, 8'h65, 8'h61, 8'h64, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f);
    patterns[344] = vec(8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h63, 8'h61, 8'h6e, 8'h76, 8'h61, 8'h73, 8'h66, 8'h6c, 8'h6f, 8'h77, 8'h2d, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h73, 8'h2d, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h26, 8'h6f);
    patterns[345] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h75, 8'h70, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h5f, 8'h66, 8'h72, 8'h6f, 8'h6d, 8'h5f, 8'h75, 8'h72, 8'h6c, 8'h26, 8'h75, 8'h72, 8'h6c);
    patterns[346] = vec(8'h2f, 8'h63, 8'h6f, 8'h6c, 8'h75, 8'h6d, 8'h62, 8'h61, 8'h6e, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h73, 8'h74, 8'h75, 8'h64, 8'h65, 8'h6e, 8'h74);
    patterns[347] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h73, 8'h62, 8'h5f, 8'h6c, 8'h69, 8'h73, 8'h74, 8'h26, 8'h73, 8'h70, 8'h6f, 8'h74, 8'h62, 8'h6f, 8'h74, 8'h5f, 8'h73);
    patterns[348] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h64, 8'h5f, 8'h6e, 8'h65, 8'h77, 8'h5f, 8'h69, 8'h74, 8'h65, 8'h6d, 8'h26, 8'h6d, 8'h65, 8'h73);
    patterns[349] = vec(8'h73, 8'h75, 8'h70, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h2f, 8'h69, 8'h6e, 8'h63, 8'h6c, 8'h75, 8'h64, 8'h65, 8'h73, 8'h2f, 8'h61, 8'h6d, 8'h70, 8'h2d, 8'h69, 8'h66, 8'h72, 8'h61, 8'h6d, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f);
    patterns[350] = vec(8'h2f, 8'h67, 8'h65, 8'h74, 8'h46, 8'h69, 8'h6c, 8'h65, 8'h54, 8'h79, 8'h70, 8'h65, 8'h4c, 8'h69, 8'h73, 8'h74, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h74, 8'h79, 8'h70, 8'h65, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h31, 8'h27);
    patterns[351] = vec(8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h73, 8'h63, 8'h68, 8'h65, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h2f, 8'h72, 8'h65, 8'h61, 8'h64, 8'h5f, 8'h6e, 8'h6f, 8'h74, 8'h65, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f);
    patterns[352] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h64, 8'h2d, 8'h73, 8'h69, 8'h74);
    patterns[353] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h46, 8'h61, 8'h76, 8'h69, 8'h63, 8'h6f, 8'h6e);
    patterns[354] = vec(8'h2f, 8'h62, 8'h6f, 8'h69, 8'h64, 8'h63, 8'h6d, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6d, 8'h65, 8'h64, 8'h69, 8'h61, 8'h26, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e);
    patterns[355] = vec(8'h2f, 8'h77, 8'h65, 8'h61, 8'h74, 8'h68, 8'h65, 8'h72, 8'h6d, 8'h61, 8'h70, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6d, 8'h61, 8'h70, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h58, 8'h58, 8'h58, 8'h25, 8'h32, 8'h32, 8'h25, 8'h32);
    patterns[356] = vec(8'h74, 8'h75, 8'h62, 8'h65, 8'h2f, 8'h66, 8'h61, 8'h73, 8'h74, 8'h2d, 8'h74, 8'h75, 8'h62, 8'h65, 8'h2d, 8'h67, 8'h61, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h26, 8'h76, 8'h70, 8'h3d, 8'h74, 8'h65);
    patterns[357] = vec(8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h6c, 8'h61, 8'h73, 8'h74, 8'h69, 8'h63, 8'h5f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h26, 8'h74, 8'h61);
    patterns[358] = vec(8'h2f, 8'h73, 8'h2f, 8'h61, 8'h72, 8'h74, 8'h69, 8'h63, 8'h6c, 8'h65, 8'h2f, 8'h43, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h3f, 8'h63, 8'h6c, 8'h61, 8'h73, 8'h73, 8'h5f, 8'h69);
    patterns[359] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h77, 8'h6f, 8'h6f, 8'h66, 8'h5f, 8'h74, 8'h65, 8'h78, 8'h74, 8'h5f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h26, 8'h76, 8'h61, 8'h6c, 8'h75, 8'h65, 8'h3d, 8'h70, 8'h72);
    patterns[360] = vec(8'h2f, 8'h67, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2f, 8'h73, 8'h61, 8'h6c, 8'h76, 8'h61, 8'h72, 8'h5f, 8'h63, 8'h61, 8'h72, 8'h67, 8'h6f, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h5f, 8'h63, 8'h61, 8'h72, 8'h67, 8'h6f);
    patterns[361] = vec(8'h5f, 8'h5f, 8'h6b, 8'h75, 8'h62, 8'h69, 8'h6f, 8'h2d, 8'h73, 8'h69, 8'h74, 8'h65, 8'h2d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2d, 8'h69, 8'h66, 8'h72, 8'h61, 8'h6d, 8'h65, 8'h2d, 8'h63, 8'h6c, 8'h61, 8'h73, 8'h73, 8'h69, 8'h63);
    patterns[362] = vec(8'h2f, 8'h66, 8'h66, 8'h6f, 8'h73, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h65, 8'h6e, 8'h75, 8'h73, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h5f, 8'h6d, 8'h65, 8'h6e, 8'h75, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f);
    patterns[363] = vec(8'h2f, 8'h69, 8'h62, 8'h6d, 8'h63, 8'h6f, 8'h67, 8'h6e, 8'h6f, 8'h73, 8'h2f, 8'h62, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h64, 8'h69, 8'h73, 8'h70, 8'h2f, 8'h69, 8'h63, 8'h64, 8'h2f, 8'h66, 8'h65, 8'h65, 8'h64, 8'h73, 8'h2f);
    patterns[364] = vec(8'h2f, 8'h3f, 8'h55, 8'h72, 8'h6b, 8'h43, 8'h45, 8'h4f, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h26, 8'h74, 8'h68, 8'h65, 8'h6d, 8'h65, 8'h3d, 8'h6d, 8'h61, 8'h72, 8'h67, 8'h6f, 8'h74, 8'h26, 8'h73, 8'h71, 8'h75, 8'h65, 8'h6c);
    patterns[365] = vec(8'h2f, 8'h63, 8'h6f, 8'h6e, 8'h73, 8'h6f, 8'h6c, 8'h65, 8'h2f, 8'h64, 8'h61, 8'h73, 8'h68, 8'h62, 8'h6f, 8'h61, 8'h72, 8'h64, 8'h2f, 8'h65, 8'h78, 8'h65, 8'h63, 8'h75, 8'h74, 8'h6f, 8'h72, 8'h43, 8'h6f, 8'h75, 8'h6e, 8'h74);
    patterns[366] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h76, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h64, 8'h2d, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2d, 8'h69, 8'h6e, 8'h74, 8'h65, 8'h67, 8'h72, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2d, 8'h6c);
    patterns[367] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h70, 8'h75, 8'h73, 8'h68, 8'h42, 8'h49, 8'h5a);
    patterns[368] = vec(8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h6c, 8'h6d, 8'h70, 8'h5f, 8'h61, 8'h64, 8'h64, 8'h50, 8'h6f, 8'h73, 8'h74, 8'h26, 8'h61, 8'h64, 8'h64, 8'h50, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h6c, 8'h69, 8'h6e, 8'h6b, 8'h49, 8'h44);
    patterns[369] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h72, 8'h33, 8'h77, 8'h69, 8'h66, 8'h26, 8'h61, 8'h63, 8'h63, 8'h65, 8'h73, 8'h73, 8'h5f, 8'h74, 8'h6f, 8'h6b);
    patterns[370] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h4d, 8'h65, 8'h6d, 8'h62, 8'h65, 8'h72, 8'h2f, 8'h6f, 8'h72, 8'h64, 8'h65, 8'h72, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h3f, 8'h4f, 8'h72);
    patterns[371] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h41, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h63, 8'h68, 8'h61, 8'h6e, 8'h6e, 8'h65, 8'h6c, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h3f, 8'h50);
    patterns[372] = vec(8'h2f, 8'h70, 8'h61, 8'h72, 8'h61, 8'h6d, 8'h65, 8'h74, 8'h65, 8'h72, 8'h2f, 8'h75, 8'h70, 8'h64, 8'h61, 8'h74, 8'h65, 8'h4e, 8'h6f, 8'h74, 8'h69, 8'h63, 8'h65, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31);
    patterns[373] = vec(8'h2f, 8'h67, 8'h65, 8'h74, 8'h4c, 8'h69, 8'h6d, 8'h69, 8'h74, 8'h49, 8'h50, 8'h4c, 8'h69, 8'h73, 8'h74, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h6e, 8'h6f, 8'h74, 8'h69, 8'h63, 8'h65, 8'h49, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00);
    patterns[374] = vec(8'h2f, 8'h73, 8'h69, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h61, 8'h2f, 8'h73, 8'h61, 8'h6c, 8'h76, 8'h61, 8'h72, 8'h5f, 8'h74, 8'h61, 8'h67, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h5f, 8'h74, 8'h61, 8'h67, 8'h3d, 8'h39);
    patterns[375] = vec(8'h2f, 8'h50, 8'h75, 8'h62, 8'h6c, 8'h69, 8'h63, 8'h2f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h69, 8'h63, 8'h73, 8'h2f, 8'h75, 8'h6d, 8'h65, 8'h64, 8'h69, 8'h74, 8'h6f, 8'h72, 8'h31, 8'h5f, 8'h32, 8'h5f, 8'h33, 8'h2f, 8'h70, 8'h68);
    patterns[376] = vec(8'h69, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h55, 8'h6e, 8'h43, 8'h68, 8'h6b, 8'h4d, 8'h61, 8'h69, 8'h6c, 8'h41, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h63, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h74, 8'h79);
    patterns[377] = vec(8'h2f, 8'h6f, 8'h70, 8'h65, 8'h6e, 8'h65, 8'h6d, 8'h72, 8'h2f, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h72, 8'h6f, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h68, 8'h61, 8'h72, 8'h6d, 8'h61, 8'h63, 8'h79);
    patterns[378] = vec(8'h6d, 8'h65, 8'h6e, 8'h75, 8'h5f, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h79, 8'h2f, 8'h73, 8'h65, 8'h61, 8'h72, 8'h63, 8'h68, 8'h5f, 8'h61, 8'h6c, 8'h6c, 8'h5f, 8'h62, 8'h79, 8'h5f, 8'h6e, 8'h61, 8'h6d, 8'h65);
    patterns[379] = vec(8'h2d, 8'h2d, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h00, 8'h2f, 8'h76, 8'h61, 8'h72, 8'h2f, 8'h72, 8'h75, 8'h6e, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2e, 8'h70, 8'h69, 8'h64, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[380] = vec(8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h64, 8'h2d, 8'h6a, 8'h6f, 8'h75, 8'h72, 8'h6e, 8'h61, 8'h6c, 8'h64, 8'h00, 8'h6b, 8'h64, 8'h6d, 8'h74, 8'h6d, 8'h70, 8'h66, 8'h6c, 8'h75, 8'h73, 8'h68, 8'h00, 8'h2f, 8'h00);
    patterns[381] = vec(8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h64, 8'h2d, 8'h6a, 8'h6f, 8'h75, 8'h72, 8'h6e, 8'h61, 8'h6c, 8'h64, 8'h00, 8'h6b, 8'h64, 8'h75, 8'h6d, 8'h70, 8'h64, 8'h62, 8'h00, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[382] = vec(8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h64, 8'h2d, 8'h6a, 8'h6f, 8'h75, 8'h72, 8'h6e, 8'h61, 8'h6c, 8'h64, 8'h00, 8'h6b, 8'h64, 8'h75, 8'h6d, 8'h70, 8'h66, 8'h6c, 8'h75, 8'h73, 8'h68, 8'h00, 8'h2f, 8'h00, 8'h00);
    patterns[383] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h61, 8'h75, 8'h74, 8'h6f, 8'h6d, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h77, 8'h6f, 8'h72, 8'h6b, 8'h66, 8'h6c, 8'h6f, 8'h77, 8'h73, 8'h3f, 8'h77, 8'h6f);
    patterns[384] = vec(8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h3d, 8'h41, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h26, 8'h63, 8'h3d, 8'h42, 8'h6f, 8'h6f, 8'h6b, 8'h26, 8'h61, 8'h3d, 8'h69, 8'h6e, 8'h64, 8'h65);
    patterns[385] = vec(8'h42, 8'h65, 8'h74, 8'h74, 8'h65, 8'h72, 8'h49, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h47, 8'h61, 8'h6c, 8'h6c, 8'h65, 8'h72, 8'h79, 8'h2f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h68, 8'h61, 8'h6e, 8'h64, 8'h6c, 8'h65, 8'h72, 8'h3f);
    patterns[386] = vec(8'h2f, 8'h62, 8'h69, 8'h72, 8'h74, 8'h68, 8'h69, 8'h6e, 8'h67, 8'h5f, 8'h72, 8'h65, 8'h63, 8'h6f, 8'h72, 8'h64, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h74, 8'h72, 8'h5f, 8'h6e, 8'h6f, 8'h3d, 8'h31, 8'h2a, 8'h00, 8'h00);
    patterns[387] = vec(8'h2f, 8'h62, 8'h69, 8'h72, 8'h74, 8'h68, 8'h69, 8'h6e, 8'h67, 8'h5f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h62, 8'h69, 8'h72, 8'h74, 8'h68, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h2a, 8'h00, 8'h00);
    patterns[388] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h62, 8'h73, 8'h61, 8'h5f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h73, 8'h5f, 8'h63, 8'h68, 8'h61, 8'h72, 8'h74, 8'h5f, 8'h63, 8'h61, 8'h6c, 8'h6c, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h26);
    patterns[389] = vec(8'h2f, 8'h7a, 8'h68, 8'h61, 8'h6e, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h2f, 8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[390] = vec(8'h2f, 8'h78, 8'h73, 8'h74, 8'h6f, 8'h72, 8'h65, 8'h6d, 8'h67, 8'h77, 8'h74, 8'h2f, 8'h63, 8'h68, 8'h65, 8'h65, 8'h74, 8'h61, 8'h68, 8'h49, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h73, 8'h3f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h49);
    patterns[391] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h2d, 8'h74, 8'h65, 8'h61, 8'h63, 8'h68, 8'h65, 8'h72, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f);
    patterns[392] = vec(8'h73, 8'h65, 8'h6c, 8'h66, 8'h2d, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h61, 8'h75, 8'h74, 8'h68, 8'h6f, 8'h72, 8'h73, 8'h3f, 8'h70, 8'h6f, 8'h73, 8'h74, 8'h5f, 8'h74, 8'h79, 8'h70);
    patterns[393] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h69, 8'h65, 8'h73, 8'h2f, 8'h76, 8'h69, 8'h65, 8'h77, 8'h5f, 8'h63, 8'h61, 8'h74);
    patterns[394] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h45, 8'h57, 8'h44, 8'h2d, 8'h46, 8'h45, 8'h55);
    patterns[395] = vec(8'h41, 8'h43, 8'h54, 8'h49, 8'h4f, 8'h4e, 8'h5f, 8'h50, 8'h4f, 8'h53, 8'h54, 8'h3d, 8'h61, 8'h64, 8'h76, 8'h5f, 8'h61, 8'h72, 8'h70, 8'h73, 8'h70, 8'h6f, 8'h6f, 8'h66, 8'h69, 8'h6e, 8'h67, 8'h26, 8'h77, 8'h68, 8'h69, 8'h63);
    patterns[396] = vec(8'h41, 8'h43, 8'h54, 8'h49, 8'h4f, 8'h4e, 8'h5f, 8'h50, 8'h4f, 8'h53, 8'h54, 8'h3d, 8'h61, 8'h64, 8'h76, 8'h5f, 8'h6d, 8'h61, 8'h63, 8'h62, 8'h79, 8'h70, 8'h61, 8'h73, 8'h73, 8'h26, 8'h66, 8'h5f, 8'h73, 8'h73, 8'h69, 8'h64);
    patterns[397] = vec(8'h41, 8'h43, 8'h54, 8'h49, 8'h4f, 8'h4e, 8'h5f, 8'h50, 8'h4f, 8'h53, 8'h54, 8'h3d, 8'h61, 8'h64, 8'h76, 8'h5f, 8'h64, 8'h68, 8'h63, 8'h70, 8'h73, 8'h26, 8'h66, 8'h5f, 8'h6d, 8'h61, 8'h63, 8'h3d, 8'h25, 8'h33, 8'h63, 8'h00);
    patterns[398] = vec(8'h2f, 8'h75, 8'h73, 8'h62, 8'h5f, 8'h70, 8'h61, 8'h73, 8'h77, 8'h64, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h73, 8'h68, 8'h61, 8'h72, 8'h65, 8'h5f, 8'h65, 8'h6e, 8'h61, 8'h62, 8'h6c, 8'h65, 8'h3d, 8'h31, 8'h26, 8'h6e, 8'h61);
    patterns[399] = vec(8'h2f, 8'h71, 8'h72, 8'h2d, 8'h63, 8'h6f, 8'h64, 8'h65, 8'h2d, 8'h62, 8'h6f, 8'h6f, 8'h6b, 8'h6d, 8'h61, 8'h72, 8'h6b, 8'h2f, 8'h65, 8'h6e, 8'h64, 8'h70, 8'h6f, 8'h69, 8'h6e, 8'h74, 8'h2f, 8'h64, 8'h65, 8'h6c, 8'h65, 8'h74);
    patterns[400] = vec(8'h2f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h76, 8'h69, 8'h74, 8'h79, 8'h2f, 8'h6e, 8'h65, 8'h77, 8'h41, 8'h63, 8'h74, 8'h69, 8'h76, 8'h69, 8'h74, 8'h79, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h44, 8'h6f);
    patterns[401] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h62, 8'h61, 8'h63, 8'h6b, 8'h75, 8'h70, 8'h2d, 8'h73, 8'h71, 8'h6c, 8'h2d, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h2f, 8'h64);
    patterns[402] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2d, 8'h74, 8'h65, 8'h61, 8'h6d, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h65, 8'h61, 8'h6d, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h27, 8'h00, 8'h00);
    patterns[403] = vec(8'h2f, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h73, 8'h61, 8'h6d, 8'h6c, 8'h5f, 8'h72, 8'h65, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74, 8'h3f, 8'h73, 8'h61, 8'h6d, 8'h6c, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h25, 8'h32, 8'h36, 8'h68, 8'h74);
    patterns[404] = vec(8'h2f, 8'h73, 8'h65, 8'h74, 8'h74, 8'h69, 8'h6e, 8'h67, 8'h73, 8'h2f, 8'h70, 8'h72, 8'h69, 8'h76, 8'h61, 8'h63, 8'h79, 8'h2d, 8'h70, 8'h6f, 8'h6c, 8'h69, 8'h63, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67);
    patterns[405] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h62, 8'h64, 8'h6e, 8'h2d, 8'h73, 8'h65);
    patterns[406] = vec(8'h69, 8'h6e, 8'h64, 8'h65, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h72, 8'h65, 8'h67, 8'h69, 8'h73, 8'h74, 8'h65, 8'h72, 8'h26, 8'h69, 8'h64, 8'h3d, 8'h31, 8'h32, 8'h33);
    patterns[407] = vec(8'h2f, 8'h62, 8'h69, 8'h6c, 8'h6c, 8'h69, 8'h6e, 8'h67, 8'h2f, 8'h70, 8'h6d, 8'h73, 8'h5f, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h69, 8'h70, 8'h61, 8'h64, 8'h64, 8'h72, 8'h65, 8'h73, 8'h73);
    patterns[408] = vec(8'h2f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h2e, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h3f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h25, 8'h32);
    patterns[409] = vec(8'h2f, 8'h67, 8'h61, 8'h6e, 8'h67, 8'h6c, 8'h69, 8'h61, 8'h2f, 8'h67, 8'h72, 8'h61, 8'h70, 8'h68, 8'h5f, 8'h61, 8'h6c, 8'h6c, 8'h5f, 8'h70, 8'h65, 8'h72, 8'h69, 8'h6f, 8'h64, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h67);
    patterns[410] = vec(8'h70, 8'h72, 8'h65, 8'h64, 8'h65, 8'h66, 8'h5f, 8'h62, 8'h77, 8'h5f, 8'h75, 8'h73, 8'h65, 8'h72, 8'h26, 8'h74, 8'h79, 8'h70, 8'h65, 8'h3d, 8'h35, 8'h6d, 8'h69, 8'h6e, 8'h73, 8'h26, 8'h74, 8'h79, 8'h70, 8'h65, 8'h5f, 8'h6e);
    patterns[411] = vec(8'h2f, 8'h6d, 8'h65, 8'h6d, 8'h62, 8'h65, 8'h72, 8'h73, 8'h2f, 8'h66, 8'h75, 8'h6e, 8'h64, 8'h44, 8'h65, 8'h74, 8'h61, 8'h69, 8'h6c, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h6d, 8'h30, 8'h36, 8'h3d, 8'h74, 8'h65, 8'h73);
    patterns[412] = vec(8'h2f, 8'h77, 8'h67, 8'h65, 8'h74, 8'h5f, 8'h74, 8'h65, 8'h73, 8'h74, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h75, 8'h6e, 8'h74, 8'h3d, 8'h31, 8'h26, 8'h75, 8'h72, 8'h6c, 8'h3d, 8'h24, 8'h28, 8'h00, 8'h00, 8'h00);
    patterns[413] = vec(8'h2f, 8'h6c, 8'h6f, 8'h67, 8'h69, 8'h6e, 8'h2e, 8'h74, 8'h64, 8'h66, 8'h3f, 8'h73, 8'h6b, 8'h69, 8'h70, 8'h6a, 8'h61, 8'h63, 8'h6b, 8'h55, 8'h73, 8'h65, 8'h72, 8'h6e, 8'h61, 8'h6d, 8'h65, 8'h3d, 8'h61, 8'h64, 8'h6d, 8'h69);
    patterns[414] = vec(8'h2f, 8'h62, 8'h61, 8'h72, 8'h62, 8'h61, 8'h72, 8'h62, 8'h61, 8'h62, 8'h61, 8'h2f, 8'h70, 8'h61, 8'h6e, 8'h65, 8'h6c, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2d, 8'h74, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65);
    patterns[415] = vec(8'h2f, 8'h70, 8'h61, 8'h6e, 8'h65, 8'h6c, 8'h2f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2d, 8'h63, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h79, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h69, 8'h64, 8'h3d);
    patterns[416] = vec(8'h6c, 8'h75, 8'h63, 8'h69, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h70, 8'h61, 8'h73, 8'h73, 8'h77, 8'h64, 8'h3f, 8'h6e, 8'h65, 8'h77, 8'h70, 8'h61, 8'h73, 8'h73);
    patterns[417] = vec(8'h2f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h2e, 8'h6a, 8'h73, 8'h6f, 8'h6e, 8'h3f, 8'h6c, 8'h6f, 8'h63, 8'h61, 8'h6c, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h2e);
    patterns[418] = vec(8'h2e, 8'h00, 8'h45, 8'h00, 8'h4e, 8'h00, 8'h43, 8'h00, 8'h52, 8'h00, 8'h54, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h59, 8'h4f, 8'h55, 8'h52, 8'h20, 8'h41, 8'h4c, 8'h4c, 8'h20, 8'h44, 8'h41, 8'h54, 8'h41, 8'h20, 8'h48, 8'h41);
    patterns[419] = vec(8'h2e, 8'h00, 8'h43, 8'h00, 8'h52, 8'h00, 8'h59, 8'h00, 8'h50, 8'h00, 8'h54, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h59, 8'h4f, 8'h55, 8'h52, 8'h20, 8'h41, 8'h4c, 8'h4c, 8'h20, 8'h44, 8'h41, 8'h54, 8'h41, 8'h20, 8'h48, 8'h41);
    patterns[420] = vec(8'h52, 8'h33, 8'h41, 8'h44, 8'h4d, 8'h33, 8'h2e, 8'h74, 8'h78, 8'h74, 8'h00, 8'h53, 8'h6b, 8'h69, 8'h70, 8'h70, 8'h69, 8'h6e, 8'h67, 8'h20, 8'h52, 8'h33, 8'h41, 8'h44, 8'h4d, 8'h33, 8'h2e, 8'h74, 8'h78, 8'h74, 8'h20, 8'h66);
    patterns[421] = vec(8'h2f, 8'h6c, 8'h75, 8'h63, 8'h69, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h72, 8'h65, 8'h62, 8'h6f, 8'h6f, 8'h74, 8'h3f, 8'h6f, 8'h70, 8'h6d, 8'h6f, 8'h64, 8'h65);
    patterns[422] = vec(8'h2f, 8'h68, 8'h65, 8'h6c, 8'h70, 8'h2f, 8'h74, 8'h6f, 8'h70, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h6c, 8'h61, 8'h6e, 8'h67, 8'h63, 8'h6f, 8'h64, 8'h65, 8'h3d, 8'h31, 8'h25, 8'h32, 8'h32, 8'h25, 8'h33, 8'h45, 8'h25, 8'h33);
    patterns[423] = vec(8'h2f, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h41, 8'h6a, 8'h61, 8'h78, 8'h3d, 8'h47, 8'h65, 8'h74, 8'h4d, 8'h6f, 8'h64, 8'h61, 8'h6c, 8'h5f, 8'h4d, 8'h51, 8'h54, 8'h54, 8'h45, 8'h64, 8'h69, 8'h74);
    patterns[424] = vec(8'h2f, 8'h3f, 8'h69, 8'h6e, 8'h73, 8'h74, 8'h61, 8'h77, 8'h70, 8'h2d, 8'h64, 8'h61, 8'h74, 8'h61, 8'h62, 8'h61, 8'h73, 8'h65, 8'h2d, 8'h6d, 8'h61, 8'h6e, 8'h61, 8'h67, 8'h65, 8'h72, 8'h3d, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e);
    patterns[425] = vec(8'h73, 8'h61, 8'h6d, 8'h70, 8'h6c, 8'h65, 8'h5f, 8'h62, 8'h75, 8'h74, 8'h74, 8'h6f, 8'h6e, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h68, 8'h65, 8'h6d, 8'h65, 8'h5f, 8'h73, 8'h74, 8'h79, 8'h6c, 8'h65, 8'h73, 8'h68);
    patterns[426] = vec(8'h2f, 8'h72, 8'h65, 8'h6c, 8'h69, 8'h61, 8'h6e, 8'h63, 8'h65, 8'h2f, 8'h53, 8'h51, 8'h4c, 8'h43, 8'h6f, 8'h6e, 8'h76, 8'h65, 8'h72, 8'h74, 8'h65, 8'h72, 8'h53, 8'h65, 8'h72, 8'h76, 8'h6c, 8'h65, 8'h74, 8'h3f, 8'h4d, 8'h79);
    patterns[427] = vec(8'h7c, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h5c, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h2f, 8'h00, 8'h20, 8'h00, 8'h5c, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h5f, 8'h00, 8'h7c, 8'h00);
    patterns[428] = vec(8'h26, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h3d, 8'h6e, 8'h65, 8'h65, 8'h64, 8'h63, 8'h68, 8'h61, 8'h6c, 8'h6c, 8'h65, 8'h6e, 8'h67, 8'h65, 8'h26, 8'h73, 8'h74, 8'h61, 8'h74, 8'h65, 8'h3d, 8'h22, 8'h3e, 8'h00, 8'h00);
    patterns[429] = vec(8'h2f, 8'h70, 8'h74, 8'h33, 8'h75, 8'h70, 8'h64, 8'h2f, 8'h2e, 8'h2e, 8'h25, 8'h32, 8'h66, 8'h2e, 8'h2e, 8'h25, 8'h32, 8'h66, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[430] = vec(8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h70, 8'h72, 8'h6f, 8'h78, 8'h79, 8'h5f, 8'h69, 8'h6d, 8'h61, 8'h67, 8'h65, 8'h26, 8'h75, 8'h72, 8'h6c, 8'h3d, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h3a, 8'h2f, 8'h2f, 8'h2f, 8'h65);
    patterns[431] = vec(8'h2f, 8'h70, 8'h75, 8'h62, 8'h6c, 8'h69, 8'h63, 8'h2f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h74, 8'h65, 8'h6d, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h65, 8'h66, 8'h69, 8'h6c);
    patterns[432] = vec(8'h2f, 8'h63, 8'h75, 8'h73, 8'h74, 8'h6f, 8'h6d, 8'h65, 8'h72, 8'h2d, 8'h63, 8'h61, 8'h62, 8'h69, 8'h6e, 8'h65, 8'h74, 8'h2f, 8'h3f, 8'h6c, 8'h61, 8'h79, 8'h6f, 8'h75, 8'h74, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f);
    patterns[433] = vec(8'h2f, 8'h70, 8'h6f, 8'h72, 8'h74, 8'h61, 8'h6c, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h31, 8'h2f, 8'h72, 8'h6f, 8'h6c, 8'h65, 8'h73, 8'h2f, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3b, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[434] = vec(8'h43, 8'h61, 8'h6e, 8'h27, 8'h74, 8'h20, 8'h6f, 8'h70, 8'h65, 8'h6e, 8'h20, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h20, 8'h61, 8'h66, 8'h74, 8'h65, 8'h72, 8'h20, 8'h6b, 8'h69, 8'h6c, 8'h6c, 8'h48, 8'h6f, 8'h6c, 8'h64, 8'h65, 8'h72);
    patterns[435] = vec(8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h62, 8'h6f, 8'h6f, 8'h6b, 8'h5f, 8'h6f, 8'h70, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h26, 8'h63, 8'h6f, 8'h77, 8'h3d, 8'h32, 8'h22, 8'h3e, 8'h00, 8'h00);
    patterns[436] = vec(8'h58, 8'h2d, 8'h4d, 8'h69, 8'h64, 8'h64, 8'h6c, 8'h65, 8'h77, 8'h61, 8'h72, 8'h65, 8'h2d, 8'h53, 8'h75, 8'h62, 8'h72, 8'h65, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74, 8'h3a, 8'h20, 8'h6d, 8'h69, 8'h64, 8'h64, 8'h6c, 8'h65, 8'h77);
    patterns[437] = vec(8'h2f, 8'h73, 8'h63, 8'h72, 8'h69, 8'h70, 8'h74, 8'h2d, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h73, 8'h63, 8'h72, 8'h69, 8'h70, 8'h74, 8'h73, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[438] = vec(8'h78, 8'h2d, 8'h6d, 8'h69, 8'h64, 8'h64, 8'h6c, 8'h65, 8'h77, 8'h61, 8'h72, 8'h65, 8'h2d, 8'h73, 8'h75, 8'h62, 8'h72, 8'h65, 8'h71, 8'h75, 8'h65, 8'h73, 8'h74, 8'h3a, 8'h20, 8'h73, 8'h72, 8'h63, 8'h2f, 8'h6d, 8'h69, 8'h64);
    patterns[439] = vec(8'h2f, 8'h6f, 8'h2f, 8'h62, 8'h6c, 8'h6f, 8'h67, 8'h73, 8'h2d, 8'h77, 8'h65, 8'h62, 8'h2f, 8'h62, 8'h6c, 8'h6f, 8'h67, 8'h73, 8'h2f, 8'h65, 8'h6e, 8'h74, 8'h72, 8'h79, 8'h5f, 8'h63, 8'h6f, 8'h76, 8'h65, 8'h72, 8'h5f, 8'h69);
    patterns[440] = vec(8'h2f, 8'h67, 8'h61, 8'h74, 8'h65, 8'h6b, 8'h65, 8'h65, 8'h70, 8'h65, 8'h72, 8'h2f, 8'h63, 8'h68, 8'h61, 8'h72, 8'h74, 8'h73, 8'h3f, 8'h61, 8'h3b, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[441] = vec(8'h2f, 8'h67, 8'h6f, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2f, 8'h77, 8'h65, 8'h62, 8'h52, 8'h65, 8'h61, 8'h64, 8'h2f, 8'h6f, 8'h70, 8'h65, 8'h6e, 8'h2f, 8'h3f, 8'h70, 8'h61, 8'h74, 8'h68, 8'h3d, 8'h25, 8'h37, 8'h43, 8'h00, 8'h00);
    patterns[442] = vec(8'h2f, 8'h76, 8'h6c, 8'h61, 8'h6e, 8'h2f, 8'h3f, 8'h76, 8'h6c, 8'h61, 8'h6e, 8'h5f, 8'h69, 8'h64, 8'h3d, 8'h25, 8'h33, 8'h43, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[443] = vec(8'h6f, 8'h6e, 8'h73, 8'h2d, 8'h67, 8'h65, 8'h6e, 8'h65, 8'h72, 8'h61, 8'h6c, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h3d, 8'h65, 8'h74, 8'h73, 8'h79, 8'h2d, 8'h73, 8'h68, 8'h6f, 8'h70, 8'h2e, 8'h70);
    patterns[444] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h53, 8'h45, 8'h4d, 8'h43, 8'h4d, 8'h53, 8'h5f, 8'h43, 8'h61, 8'h74, 8'h65, 8'h67, 8'h6f, 8'h72, 8'h69, 8'h65, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h74, 8'h79, 8'h70);
    patterns[445] = vec(8'h24, 8'h35, 8'h24, 8'h00, 8'h24, 8'h36, 8'h24, 8'h00, 8'h24, 8'h32, 8'h61, 8'h24, 8'h00, 8'h72, 8'h6f, 8'h75, 8'h6e, 8'h64, 8'h73, 8'h3d, 8'h25, 8'h75, 8'h24, 8'h00, 8'h2a, 8'h4e, 8'h50, 8'h2a, 8'h00, 8'h24, 8'h31, 8'h24);
    patterns[446] = vec(8'h6c, 8'h6b, 8'h69, 8'h69, 8'h73, 8'h2f, 8'h6e, 8'h68, 8'h72, 8'h25, 8'h72, 8'h7b, 8'h71, 8'h72, 8'h68, 8'h7d, 8'h63, 8'h71, 8'h7b, 8'h3d, 8'h7e, 8'h05, 8'h37, 8'h65, 8'h6d, 8'h7d, 8'h68, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[447] = vec(8'h2d, 8'h2d, 8'h63, 8'h68, 8'h61, 8'h72, 8'h67, 8'h65, 8'h00, 8'h2d, 8'h67, 8'h74, 8'h70, 8'h76, 8'h00, 8'h2d, 8'h73, 8'h59, 8'h00, 8'h2d, 8'h73, 8'h59, 8'h73, 8'h00, 8'h2d, 8'h50, 8'h6e, 8'h00, 8'h2d, 8'h6f, 8'h4e, 8'h00);
    patterns[448] = vec(8'h70, 8'h67, 8'h77, 8'h2d, 8'h73, 8'h35, 8'h73, 8'h38, 8'h2e, 8'h6d, 8'h70, 8'h67, 8'h77, 8'h30, 8'h30, 8'h31, 8'h2e, 8'h6e, 8'h6f, 8'h64, 8'h65, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[449] = vec(8'h73, 8'h65, 8'h74, 8'h73, 8'h6f, 8'h63, 8'h6b, 8'h6f, 8'h70, 8'h74, 8'h20, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72, 8'h21, 8'h00, 8'h69, 8'h64, 8'h6b, 8'h65, 8'h79, 8'h20, 8'h6e, 8'h6f, 8'h74, 8'h20, 8'h63, 8'h6f, 8'h72, 8'h72);
    patterns[450] = vec(8'h2f, 8'h44, 8'h65, 8'h76, 8'h69, 8'h63, 8'h65, 8'h73, 8'h47, 8'h61, 8'h74, 8'h65, 8'h77, 8'h61, 8'h79, 8'h2f, 8'h61, 8'h70, 8'h70, 8'h73, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2d, 8'h61, 8'h70, 8'h70, 8'h2d);
    patterns[451] = vec(8'h73, 8'h6d, 8'h73, 8'h5f, 8'h72, 8'h65, 8'h63, 8'h65, 8'h69, 8'h76, 8'h65, 8'h64, 8'h5f, 8'h66, 8'h6c, 8'h61, 8'h67, 8'h5f, 8'h66, 8'h6c, 8'h61, 8'h67, 8'h3d, 8'h30, 8'h26, 8'h73, 8'h74, 8'h73, 8'h5f, 8'h72, 8'h65, 8'h63);
    patterns[452] = vec(8'h2f, 8'h4f, 8'h41, 8'h5f, 8'h48, 8'h54, 8'h4d, 8'h4c, 8'h2f, 8'h68, 8'h65, 8'h6c, 8'h70, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[453] = vec(8'h2f, 8'h68, 8'h74, 8'h74, 8'h70, 8'h64, 8'h5f, 8'h64, 8'h65, 8'h62, 8'h75, 8'h67, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h74, 8'h69, 8'h6d, 8'h65, 8'h3d, 8'h25, 8'h32, 8'h32, 8'h25, 8'h32, 8'h30, 8'h25, 8'h32, 8'h34, 8'h00);
    patterns[454] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h6c, 8'h69, 8'h76, 8'h65, 8'h5f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2f, 8'h6c, 8'h69, 8'h76, 8'h65, 8'h5f, 8'h65, 8'h64, 8'h69, 8'h74, 8'h2e, 8'h6d, 8'h6f, 8'h64, 8'h75, 8'h6c, 8'h65, 8'h5f);
    patterns[455] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h2d, 8'h70, 8'h72, 8'h6f, 8'h6a, 8'h65, 8'h63, 8'h74, 8'h2d, 8'h70, 8'h64, 8'h66, 8'h3f, 8'h70, 8'h72, 8'h6f, 8'h6a, 8'h65, 8'h63);
    patterns[456] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h70, 8'h61, 8'h67, 8'h65, 8'h2f, 8'h63, 8'h72, 8'h65, 8'h61, 8'h74, 8'h65, 8'h3f, 8'h6c, 8'h61, 8'h79, 8'h6f, 8'h75, 8'h74, 8'h3d, 8'h22, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[457] = vec(8'h73, 8'h73, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h25, 8'h73, 8'h0d, 8'h0a, 8'h00, 8'h25, 8'h32, 8'h35, 8'h35, 8'h5b, 8'h5e, 8'h3a, 8'h5d, 8'h3a, 8'h25, 8'h64, 8'h2b, 8'h25, 8'h36, 8'h34, 8'h5b, 8'h5e, 8'h2b, 8'h5d, 8'h25, 8'h64);
    patterns[458] = vec(8'h2f, 8'h74, 8'h72, 8'h75, 8'h66, 8'h75, 8'h73, 8'h69, 8'h6f, 8'h6e, 8'h50, 8'h6f, 8'h72, 8'h74, 8'h61, 8'h6c, 8'h2f, 8'h67, 8'h65, 8'h74, 8'h43, 8'h6f, 8'h62, 8'h72, 8'h61, 8'h6e, 8'h64, 8'h69, 8'h6e, 8'h67, 8'h44, 8'h61);
    patterns[459] = vec(8'h6c, 8'h69, 8'h6e, 8'h6b, 8'h2d, 8'h63, 8'h6c, 8'h69, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h65, 8'h62, 8'h70, 8'h66, 8'h2e, 8'h28, 8'h2a, 8'h68, 8'h69, 8'h64, 8'h65, 8'h50, 8'h72, 8'h6f, 8'h67, 8'h72, 8'h61, 8'h6d, 8'h73, 8'h29);
    patterns[460] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h6d, 8'h79, 8'h2d, 8'h72, 8'h65, 8'h73, 8'h65, 8'h72, 8'h76, 8'h61, 8'h74, 8'h69);
    patterns[461] = vec(8'h2f, 8'h68, 8'h61, 8'h70, 8'h72, 8'h6f, 8'h78, 8'h79, 8'h2f, 8'h68, 8'h61, 8'h70, 8'h72, 8'h6f, 8'h78, 8'h79, 8'h5f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h73, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h73, 8'h68, 8'h6f, 8'h77, 8'h73);
    patterns[462] = vec(8'h2f, 8'h73, 8'h75, 8'h72, 8'h69, 8'h63, 8'h61, 8'h74, 8'h61, 8'h5f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h63, 8'h68, 8'h65, 8'h63, 8'h6b, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h68, 8'h61, 8'h73, 8'h68);
    patterns[463] = vec(8'h2f, 8'h74, 8'h69, 8'h6c, 8'h65, 8'h73, 8'h65, 8'h72, 8'h76, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h78, 8'h2f, 8'h31, 8'h2f, 8'h31, 8'h2f, 8'h31, 8'h3f, 8'h46, 8'h6f, 8'h72, 8'h6d, 8'h61, 8'h74, 8'h3d, 8'h2f);
    patterns[464] = vec(8'h2f, 8'h74, 8'h69, 8'h6c, 8'h65, 8'h73, 8'h65, 8'h72, 8'h76, 8'h65, 8'h72, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h77, 8'h6d, 8'h74, 8'h73, 8'h2f, 8'h78, 8'h2f, 8'h31, 8'h2f, 8'h31, 8'h2f, 8'h61, 8'h73, 8'h64, 8'h3f, 8'h52);
    patterns[465] = vec(8'h2f, 8'h5f, 8'h5f, 8'h64, 8'h65, 8'h62, 8'h75, 8'h67, 8'h67, 8'h69, 8'h6e, 8'h67, 8'h5f, 8'h63, 8'h65, 8'h6e, 8'h74, 8'h65, 8'h72, 8'h5f, 8'h75, 8'h74, 8'h69, 8'h6c, 8'h73, 8'h5f, 8'h5f, 8'h5f, 8'h2e, 8'h70, 8'h68, 8'h70);
    patterns[466] = vec(8'h61, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h63, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h67, 8'h72, 8'h6f, 8'h6f, 8'h76, 8'h79, 8'h73, 8'h63, 8'h72, 8'h69, 8'h70, 8'h74, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h3b);
    patterns[467] = vec(8'h2f, 8'h68, 8'h74, 8'h6d, 8'h6c, 8'h2f, 8'h73, 8'h6f, 8'h63, 8'h69, 8'h6f, 8'h2f, 8'h73, 8'h69, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h61, 8'h2f, 8'h64, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h5f, 8'h72, 8'h65, 8'h6d);
    patterns[468] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h32, 8'h2e, 8'h30, 8'h2f, 8'h63, 8'h6d, 8'h64, 8'h62, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h25, 8'h33, 8'h46, 8'h2f, 8'h2e);
    patterns[469] = vec(8'h53, 8'h55, 8'h42, 8'h53, 8'h43, 8'h52, 8'h49, 8'h42, 8'h45, 8'h20, 8'h2f, 8'h67, 8'h65, 8'h6e, 8'h61, 8'h2e, 8'h63, 8'h67, 8'h69, 8'h3f, 8'h73, 8'h65, 8'h72, 8'h76, 8'h69, 8'h63, 8'h65, 8'h3d, 8'h5c, 8'h5c, 8'h60, 8'h00);
    patterns[470] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h63, 8'h6f, 8'h6e, 8'h74, 8'h65, 8'h6e, 8'h74, 8'h2f, 8'h70, 8'h6c, 8'h75, 8'h67, 8'h69, 8'h6e, 8'h73, 8'h2f, 8'h74, 8'h72, 8'h69, 8'h6e, 8'h69, 8'h74, 8'h79, 8'h2d, 8'h61, 8'h75, 8'h64, 8'h69);
    patterns[471] = vec(8'h61, 8'h70, 8'h70, 8'h6c, 8'h69, 8'h63, 8'h61, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h73, 8'h2f, 8'h67, 8'h72, 8'h6f, 8'h6f, 8'h76, 8'h79, 8'h73, 8'h63, 8'h72, 8'h69, 8'h70, 8'h74, 8'h73, 8'h74, 8'h61, 8'h74, 8'h75, 8'h73, 8'h3f);
    patterns[472] = vec(8'h2f, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h73, 8'h73, 8'h78, 8'h2f, 8'h4d, 8'h61, 8'h69, 8'h6e, 8'h2f, 8'h57, 8'h65, 8'h62, 8'h48, 8'h6f, 8'h6d, 8'h65, 8'h3f, 8'h72, 8'h65, 8'h73, 8'h6f, 8'h75, 8'h72, 8'h63, 8'h65, 8'h3d, 8'h2e);
    patterns[473] = vec(8'h54, 8'h61, 8'h62, 8'h6c, 8'h65, 8'h41, 8'h6e, 8'h64, 8'h43, 8'h6f, 8'h6c, 8'h75, 8'h6d, 8'h6e, 8'h4e, 8'h61, 8'h6d, 8'h65, 8'h3f, 8'h63, 8'h6f, 8'h6c, 8'h75, 8'h6d, 8'h6e, 8'h4e, 8'h61, 8'h6d, 8'h65, 8'h69, 8'h64, 8'h3d);
    patterns[474] = vec(8'h2f, 8'h63, 8'h67, 8'h69, 8'h2d, 8'h62, 8'h69, 8'h6e, 8'h2f, 8'h44, 8'h6f, 8'h77, 8'h6e, 8'h6c, 8'h6f, 8'h61, 8'h64, 8'h43, 8'h66, 8'h67, 8'h2e, 8'h6a, 8'h70, 8'h67, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[475] = vec(8'h2f, 8'h5f, 8'h5f, 8'h73, 8'h63, 8'h72, 8'h65, 8'h65, 8'h6e, 8'h73, 8'h68, 8'h6f, 8'h74, 8'h2d, 8'h65, 8'h72, 8'h72, 8'h6f, 8'h72, 8'h3f, 8'h66, 8'h69, 8'h6c, 8'h65, 8'h3d, 8'h2e, 8'h2e, 8'h2f, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[476] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[477] = vec(8'h2f, 8'h77, 8'h70, 8'h2d, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h2d, 8'h61, 8'h6a, 8'h61, 8'h78, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d);
    patterns[478] = vec(8'h67, 8'h75, 8'h65, 8'h73, 8'h74, 8'h41, 8'h63, 8'h63, 8'h65, 8'h73, 8'h73, 8'h53, 8'h75, 8'h62, 8'h6d, 8'h69, 8'h74, 8'h2e, 8'h6a, 8'h73, 8'h70, 8'h3f, 8'h63, 8'h6f, 8'h6f, 8'h6b, 8'h69, 8'h65, 8'h3d, 8'h6e, 8'h75, 8'h6c);
    patterns[479] = vec(8'h2f, 8'h6d, 8'h6e, 8'h67, 8'h5f, 8'h70, 8'h6c, 8'h61, 8'h74, 8'h66, 8'h6f, 8'h72, 8'h6d, 8'h2e, 8'h61, 8'h73, 8'h70, 8'h3f, 8'h61, 8'h64, 8'h64, 8'h72, 8'h3d, 8'h60, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[480] = vec(8'h2f, 8'h67, 8'h65, 8'h74, 8'h63, 8'h66, 8'h67, 8'h2e, 8'h70, 8'h68, 8'h70, 8'h3f, 8'h61, 8'h3d, 8'h25, 8'h30, 8'h41, 8'h5f, 8'h50, 8'h4f, 8'h53, 8'h54, 8'h5f, 8'h53, 8'h45, 8'h52, 8'h56, 8'h49, 8'h43, 8'h45, 8'h53, 8'h3d);
    patterns[481] = vec(8'h2f, 8'h66, 8'h69, 8'h6c, 8'h74, 8'h65, 8'h72, 8'h2f, 8'h6a, 8'h6d, 8'h6f, 8'h6c, 8'h2f, 8'h6a, 8'h73, 8'h2f, 8'h6a, 8'h73, 8'h6d, 8'h6f, 8'h6c, 8'h2f, 8'h70, 8'h68, 8'h70, 8'h2f, 8'h6a, 8'h73, 8'h6d, 8'h6f, 8'h6c, 8'h2e);
    patterns[482] = vec(8'h2f, 8'h61, 8'h67, 8'h65, 8'h6e, 8'h74, 8'h70, 8'h75, 8'h73, 8'h68, 8'h50, 8'h72, 8'h65, 8'h73, 8'h65, 8'h74, 8'h2e, 8'h68, 8'h74, 8'h6d, 8'h6c, 8'h3f, 8'h61, 8'h63, 8'h74, 8'h69, 8'h6f, 8'h6e, 8'h3d, 8'h6e, 8'h65, 8'h77);
    patterns[483] = vec(8'h2f, 8'h61, 8'h64, 8'h6d, 8'h69, 8'h6e, 8'h75, 8'h69, 8'h2f, 8'h64, 8'h65, 8'h62, 8'h75, 8'h67, 8'h3f, 8'h64, 8'h65, 8'h62, 8'h75, 8'h67, 8'h3d, 8'h4f, 8'h47, 8'h4e, 8'h4c, 8'h25, 8'h33, 8'h41, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[484] = vec(8'h2f, 8'h61, 8'h70, 8'h69, 8'h2f, 8'h76, 8'h32, 8'h2e, 8'h30, 8'h2f, 8'h73, 8'h79, 8'h73, 8'h74, 8'h65, 8'h6d, 8'h2f, 8'h73, 8'h74, 8'h61, 8'h74, 8'h65, 8'h25, 8'h30, 8'h30, 8'h2f, 8'h2e, 8'h2e, 8'h2f, 8'h2e, 8'h2e, 8'h2f);
    patterns[485] = vec(8'h77, 8'h70, 8'h5f, 8'h73, 8'h6b, 8'h69, 8'h74, 8'h74, 8'h65, 8'h72, 8'h5f, 8'h73, 8'h6c, 8'h69, 8'h64, 8'h65, 8'h73, 8'h3d, 8'h22, 8'h3e, 8'h3c, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[486] = vec(8'h2f, 8'h6d, 8'h73, 8'h70, 8'h5f, 8'h69, 8'h6e, 8'h66, 8'h6f, 8'h2e, 8'h68, 8'h74, 8'h6d, 8'h3f, 8'h66, 8'h6c, 8'h61, 8'h67, 8'h3d, 8'h63, 8'h6d, 8'h64, 8'h26, 8'h63, 8'h6d, 8'h64, 8'h3d, 8'h7c, 8'h00, 8'h00, 8'h00, 8'h00);
    patterns[487] = vec(8'h6d, 8'h65, 8'h74, 8'h74, 8'h6c, 8'h65, 8'h20, 8'h2d, 8'h55, 8'h20, 8'h22, 8'h54, 8'h31, 8'h61, 8'h72, 8'h68, 8'h61, 8'h6a, 8'h65, 8'h30, 8'h64, 8'h34, 8'h51, 8'h69, 8'h42, 8'h61, 8'h4a, 8'h65, 8'h62, 8'h62, 8'h6a, 8'h50);
    patterns[488] = vec(8'h6d, 8'h65, 8'h74, 8'h74, 8'h6c, 8'h65, 8'h20, 8'h2d, 8'h55, 8'h20, 8'h22, 8'h6e, 8'h33, 8'h31, 8'h73, 8'h4d, 8'h65, 8'h39, 8'h52, 8'h6e, 8'h34, 8'h77, 8'h4e, 8'h71, 8'h51, 8'h75, 8'h6f, 8'h5a, 8'h4a, 8'h61, 8'h4f, 8'h65);
    patterns[489] = vec(8'h6d, 8'h65, 8'h74, 8'h74, 8'h6c, 8'h65, 8'h20, 8'h2d, 8'h55, 8'h20, 8'h22, 8'h59, 8'h6f, 8'h54, 8'h6b, 8'h49, 8'h35, 8'h73, 8'h74, 8'h4e, 8'h6a, 8'h52, 8'h73, 8'h45, 8'h57, 8'h6f, 8'h51, 8'h42, 8'h53, 8'h37, 8'h35, 8'h56);
    patterns[490] = vec(8'h5b, 8'h6d, 8'h61, 8'h69, 8'h6e, 8'h5d, 8'h20, 8'h63, 8'h6f, 8'h6e, 8'h6e, 8'h65, 8'h63, 8'h74, 8'h65, 8'h64, 8'h20, 8'h74, 8'h6f, 8'h20, 8'h43, 8'h4e, 8'h43, 8'h2e, 8'h00, 8'h00, 8'h00, 8'h00, 8'h01, 8'h00, 8'h65, 8'h78);
    patterns[491] = vec(8'h29, 8'h34, 8'h34, 8'h34, 8'h34, 8'h34, 8'h34, 8'h34, 8'h34, 8'h34, 8'h14, 8'h34, 8'h34, 8'h46, 8'h53, 8'h6e, 8'h51, 8'h48, 8'h63, 8'h3b, 8'h00, 8'h3e, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00);
    return patterns;
endfunction

