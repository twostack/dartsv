class OpCodes {

  //thanks for the OpCode Map MoneyButton/bsv ;)
  static const opcodeMap = {
    // push value
    "OP_FALSE": 0,
    "OP_0": 0,
    "OP_PUSHDATA1": 76,
    "OP_PUSHDATA2": 77,
    "OP_PUSHDATA4": 78,
    "OP_1NEGATE": 79,
    "OP_RESERVED": 80,
    "OP_TRUE": 81,
    "OP_1": 81,
    "OP_2": 82,
    "OP_3": 83,
    "OP_4": 84,
    "OP_5": 85,
    "OP_6": 86,
    "OP_7": 87,
    "OP_8": 88,
    "OP_9": 89,
    "OP_10": 90,
    "OP_11": 91,
    "OP_12": 92,
    "OP_13": 93,
    "OP_14": 94,
    "OP_15": 95,
    "OP_16": 96,

    // control
    "OP_NOP": 97,
    "OP_VER": 98,
    "OP_IF": 99,
    "OP_NOTIF": 100,
    "OP_VERIF": 101,
    "OP_VERNOTIF": 102,
    "OP_ELSE": 103,
    "OP_ENDIF": 104,
    "OP_VERIFY": 105,
    "OP_RETURN": 106,

    // stack ops
    "OP_TOALTSTACK": 107,
    "OP_FROMALTSTACK": 108,
    "OP_2DROP": 109,
    "OP_2DUP": 110,
    "OP_3DUP": 111,
    "OP_2OVER": 112,
    "OP_2ROT": 113,
    "OP_2SWAP": 114,
    "OP_IFDUP": 115,
    "OP_DEPTH": 116,
    "OP_DROP": 117,
    "OP_DUP": 118,
    "OP_NIP": 119,
    "OP_OVER": 120,
    "OP_PICK": 121,
    "OP_ROLL": 122,
    "OP_ROT": 123,
    "OP_SWAP": 124,
    "OP_TUCK": 125,

    // splice ops
    "OP_CAT": 126,
    "OP_SPLIT": 127,
    "OP_NUM2BIN": 128,
    "OP_BIN2NUM": 129,
    "OP_SIZE": 130,

    // bit logic
    "OP_INVERT": 131,
    "OP_AND": 132,
    "OP_OR": 133,
    "OP_XOR": 134,
    "OP_EQUAL": 135,
    "OP_EQUALVERIFY": 136,
    "OP_RESERVED1": 137,
    "OP_RESERVED2": 138,

    // numeric
    "OP_1ADD": 139,
    "OP_1SUB": 140,
    "OP_2MUL": 141,
    "OP_2DIV": 142,
    "OP_NEGATE": 143,
    "OP_ABS": 144,
    "OP_NOT": 145,
    "OP_0NOTEQUAL": 146,

    "OP_ADD": 147,
    "OP_SUB": 148,
    "OP_MUL": 149,
    "OP_DIV": 150,
    "OP_MOD": 151,
    "OP_LSHIFT": 152,
    "OP_RSHIFT": 153,

    "OP_BOOLAND": 154,
    "OP_BOOLOR": 155,
    "OP_NUMEQUAL": 156,
    "OP_NUMEQUALVERIFY": 157,
    "OP_NUMNOTEQUAL": 158,
    "OP_LESSTHAN": 159,
    "OP_GREATERTHAN": 160,
    "OP_LESSTHANOREQUAL": 161,
    "OP_GREATERTHANOREQUAL": 162,
    "OP_MIN": 163,
    "OP_MAX": 164,

    "OP_WITHIN": 165,

    // crypto
    "OP_RIPEMD160": 166,
    "OP_SHA1": 167,
    "OP_SHA256": 168,
    "OP_HASH160": 169,
    "OP_HASH256": 170,
    "OP_CODESEPARATOR": 171,
    "OP_CHECKSIG": 172,
    "OP_CHECKSIGVERIFY": 173,
    "OP_CHECKMULTISIG": 174,
    "OP_CHECKMULTISIGVERIFY": 175,

    "OP_CHECKLOCKTIMEVERIFY": 177,
    "OP_CHECKSEQUENCEVERIFY": 178,

    // expansion
    "OP_NOP1": 176,
    "OP_NOP2": 177,
    "OP_NOP3": 178,
    "OP_NOP4": 179,
    "OP_NOP5": 180,
    "OP_NOP6": 181,
    "OP_NOP7": 182,
    "OP_NOP8": 183,
    "OP_NOP9": 184,
    "OP_NOP10": 185,

    // template matching params
    "OP_PUBKEYHASH": 253,
    "OP_PUBKEY": 254,
    "OP_INVALIDOPCODE": 255
  };

// push value
  static const int OP_FALSE = 0;
  static const int OP_0 = 0;
  static const int OP_PUSHDATA1 = 76;
  static const int OP_PUSHDATA2 = 77;
  static const int OP_PUSHDATA4 = 78;
  static const int OP_1NEGATE = 79;
  static const int OP_RESERVED = 80;
  static const int OP_TRUE = 81;
  static const int OP_1 = 81;
  static const int OP_2 = 82;
  static const int OP_3 = 83;
  static const int OP_4 = 84;
  static const int OP_5 = 85;
  static const int OP_6 = 86;
  static const int OP_7 = 87;
  static const int OP_8 = 88;
  static const int OP_9 = 89;
  static const int OP_10 = 90;
  static const int OP_11 = 91;
  static const int OP_12 = 92;
  static const int OP_13 = 93;
  static const int OP_14 = 94;
  static const int OP_15 = 95;
  static const int OP_16 = 96;

// control
  static const int OP_NOP = 97;
  static const int OP_VER = 98;
  static const int OP_IF = 99;
  static const int OP_NOTIF = 100;
  static const int OP_VERIF = 101;
  static const int OP_VERNOTIF = 102;
  static const int OP_ELSE = 103;
  static const int OP_ENDIF = 104;
  static const int OP_VERIFY = 105;
  static const int OP_RETURN = 106;

// stack ops
  static const int OP_TOALTSTACK = 107;
  static const int OP_FROMALTSTACK = 108;
  static const int OP_2DROP = 109;
  static const int OP_2DUP = 110;
  static const int OP_3DUP = 111;
  static const int OP_2OVER = 112;
  static const int OP_2ROT = 113;
  static const int OP_2SWAP = 114;
  static const int OP_IFDUP = 115;
  static const int OP_DEPTH = 116;
  static const int OP_DROP = 117;
  static const int OP_DUP = 118;
  static const int OP_NIP = 119;
  static const int OP_OVER = 120;
  static const int OP_PICK = 121;
  static const int OP_ROLL = 122;
  static const int OP_ROT = 123;
  static const int OP_SWAP = 124;
  static const int OP_TUCK = 125;

// splice ops
  static const int OP_CAT = 126;
  static const int OP_SPLIT = 127;
  static const int OP_NUM2BIN = 128;
  static const int OP_BIN2NUM = 129;
  static const int OP_SIZE = 130;

// bit logic
  static const int OP_INVERT = 131;
  static const int OP_AND = 132;
  static const int OP_OR = 133;
  static const int OP_XOR = 134;
  static const int OP_EQUAL = 135;
  static const int OP_EQUALVERIFY = 136;
  static const int OP_RESERVED1 = 137;
  static const int OP_RESERVED2 = 138;

// numeric
  static const int OP_1ADD = 139;
  static const int OP_1SUB = 140;
  static const int OP_2MUL = 141;
  static const int OP_2DIV = 142;
  static const int OP_NEGATE = 143;
  static const int OP_ABS = 144;
  static const int OP_NOT = 145;
  static const int OP_0NOTEQUAL = 146;

  static const int OP_ADD = 147;
  static const int OP_SUB = 148;
  static const int OP_MUL = 149;
  static const int OP_DIV = 150;
  static const int OP_MOD = 151;
  static const int OP_LSHIFT = 152;
  static const int OP_RSHIFT = 153;

  static const int OP_BOOLAND = 154;
  static const int OP_BOOLOR = 155;
  static const int OP_NUMEQUAL = 156;
  static const int OP_NUMEQUALVERIFY = 157;
  static const int OP_NUMNOTEQUAL = 158;
  static const int OP_LESSTHAN = 159;
  static const int OP_GREATERTHAN = 160;
  static const int OP_LESSTHANOREQUAL = 161;
  static const int OP_GREATERTHANOREQUAL = 162;
  static const int OP_MIN = 163;
  static const int OP_MAX = 164;

  static const int OP_WITHIN = 165;

// crypto
  static const int OP_RIPEMD160 = 166;
  static const int OP_SHA1 = 167;
  static const int OP_SHA256 = 168;
  static const int OP_HASH160 = 169;
  static const int OP_HASH256 = 170;
  static const int OP_CODESEPARATOR = 171;
  static const int OP_CHECKSIG = 172;
  static const int OP_CHECKSIGVERIFY = 173;
  static const int OP_CHECKMULTISIG = 174;
  static const int OP_CHECKMULTISIGVERIFY = 175;

  static const int OP_CHECKLOCKTIMEVERIFY = 177;
  static const int OP_CHECKSEQUENCEVERIFY = 178;

// expansion
  static const int OP_NOP1 = 176;
  static const int OP_NOP2 = 177;
  static const int OP_NOP3 = 178;
  static const int OP_NOP4 = 179;
  static const int OP_NOP5 = 180;
  static const int OP_NOP6 = 181;
  static const int OP_NOP7 = 182;
  static const int OP_NOP8 = 183;
  static const int OP_NOP9 = 184;
  static const int OP_NOP10 = 185;

// template matching params
  static const int OP_PUBKEYHASH = 253;
  static const int OP_PUBKEY = 254;
  static const int OP_INVALIDOPCODE = 255;

}
