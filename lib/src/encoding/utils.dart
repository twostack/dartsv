
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/varint.dart';
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';

import 'package:pointycastle/export.dart';

List<int> sha256Twice(List<int> bytes) {
  var first = new SHA256Digest().process(Uint8List.fromList(bytes));
  var second = new SHA256Digest().process(first);
  return second.toList();
}

List<int> sha256(List<int> bytes) {
  return new SHA256Digest().process(Uint8List.fromList(bytes)).toList();
}

List<int> sha1(List<int> bytes) {
  return new SHA1Digest().process(Uint8List.fromList(bytes)).toList();
}

List<int> hash160(List<int> bytes) {
  List<int> shaHash = new SHA256Digest().process(Uint8List.fromList(bytes));
  var ripeHash = new RIPEMD160Digest().process(shaHash as Uint8List);
  return ripeHash.toList();
}

List<int> ripemd160(List<int> bytes) {
  var ripeHash = new RIPEMD160Digest().process(Uint8List.fromList(bytes));
  return ripeHash.toList();
}

int hexToUint16(List<int> hexBuffer) {
  return int.parse(HEX.encode(hexBuffer), radix: 16).toUnsigned(16);
}

int hexToInt32(List<int> hexBuffer) {
  return int.parse(HEX.encode(hexBuffer), radix: 16).toSigned(32);
}

int hexToUint32(List<int> hexBuffer) {
  return int.parse(HEX.encode(hexBuffer), radix: 16).toUnsigned(32);
}

int hexToInt64(List<int> hexBuffer) {
  return int.parse(HEX.encode(hexBuffer), radix: 16).toSigned(64);
}

BigInt hexToUint64(List<int> hexBuffer) {
  return BigInt.parse(HEX.encode(hexBuffer), radix: 16).toUnsigned(64);
}

// List<int> varintBufNum(n) {
// //    List<int> buf ;
//   ByteDataWriter writer = ByteDataWriter();
//   if (n < 253) {
//     writer.writeUint8(n);
//   } else if (n < 0x10000) {
//     writer.writeUint8(253);
//     writer.writeUint16(n, Endian.little);
//   } else if (n < 0x100000000) {
//     writer.writeUint8(254);
//     writer.writeUint32(n, Endian.little);
//   } else {
//     writer.writeUint8(255);
//     writer.writeInt32(n & -1, Endian.little);
//     writer.writeUint32((n / 0x100000000).floor(), Endian.little);
//   }
//   return writer.toBytes().toList();
// }


Uint8List varIntWriter(int? length) {
  ByteDataWriter writer = ByteDataWriter();

  if (length == null) {
    return writer.toBytes();
  }

  if (length < 0xFD) {
    writer.writeUint8(length);
    return writer.toBytes();
  }

  if (length < 0xFFFF) {
//            return HEX.decode("FD" + length.toRadixString(16));
    writer.writeUint8(253);
    writer.writeUint16(length, Endian.little);
    return writer.toBytes();
  }

  if (length < 0xFFFFFFFF) {
//            return HEX.decode("FE" + length.toRadixString(16));

    writer.writeUint8(254);
    writer.writeUint32(length, Endian.little);
    return writer.toBytes();
  }

  if (BigInt.parse("0xFFFFFFFFFFFFFFFF").compareTo(BigInt.from(length)) == -1) {
//            return HEX.decode("FF" + length.toRadixString(16));

    writer.writeUint8(255);
    writer.writeInt32(length & -1, Endian.little);
    writer.writeUint32((length / 0x100000000).floor(), Endian.little);
    return writer.toBytes();
  }

  return writer.toBytes();
}

/**
 * Returns the minimum encoded size of the given unsigned long value.
 *
 * @param value the unsigned long value (beware widening conversion of negatives!)
 */
int sizeOf(int value) {
  // if negative, it's actually a very large unsigned long value
  if (value < 0) return 9; // 1 marker + 8 data bytes
  if (value < 253) return 1; // 1 data byte
  if (value <= 0xFFFF) return 3; // 1 marker + 2 data bytes
  if (value <= 0xFFFFFFFF) return 5; // 1 marker + 4 data bytes
  return 9; // 1 marker + 8 data bytes
}

List<int> calcVarInt(int value) {
  var writer = ByteDataWriter();
  switch (sizeOf(value)) {
    case 1:
      return [value];
    case 3:
      writer.writeUint8(253);
      writer.writeUint16(value, Endian.little);
      return writer.toBytes();
    case 5:
      writer.writeUint8(254);
      writer.writeUint32(value, Endian.little);
      return writer.toBytes();

    default:
      writer.writeUint8(255);
      writer.writeInt64(value, Endian.little);
      return writer.toBytes();
  }
}

int readVarIntNum(ByteDataReader reader) {
  var varint = VarInt.fromStream(reader);
  return varint.value;
}

//FIXME: Should probably have two versions of this function. One for BigInt, one for Int
BigInt readVarInt(Uint8List buffer) {
  var first =
      int.parse(HEX.encode(buffer.sublist(0, 1)), radix: 16).toUnsigned(8);

  switch (first) {
    case 0xFD:
      return BigInt.from(
          hexToUint16(buffer.sublist(1, 3))); //2 bytes ==  Uint16

    case 0xFE:
      return BigInt.from(hexToUint32(buffer.sublist(1, 5))); //4 bytes == Uint32

    case 0xFF:
      return hexToUint64(buffer.sublist(1, 9)); //8 bytes == Uint64

    default:
      return BigInt.from(first);
  }
}


List<int> encodeBigIntLE(BigInt number) {
  int size = 8;

  var result = Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }

  return result.reversed.toList();
}

Uint8List encodeBigIntSV(BigInt number) {
  int size = (number.bitLength + 7) >> 3;

  if (size == 0) size = 8; //always padd to 64 bits if zero

  var result = Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }

  return result;
}
//
// /// Decode a BigInt from bytes in big-endian encoding.
BigInt decodeBigIntSV(List<int> bytes) {
  BigInt result = new BigInt.from(0);

  for (int i = 0; i < bytes.length; i++) {
    result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }

  return result;
}

var _byteMask = new BigInt.from(0xff);

List<int> castToBuffer(BigInt value) {
  return toSM(value, endian: Endian.little);
}

BigInt castToBigInt(List<int> buf, bool fRequireMinimal, {int nMaxNumSize = 4}) {
  if (!(buf.length <= nMaxNumSize)) {
    throw new ScriptException(ScriptError.SCRIPT_ERR_NUMBER_OVERFLOW, 'script number overflow');
  }

  if (fRequireMinimal && buf.length > 0) {
    // Check that the number is encoded with the minimum possible
    // number of bytes.
    //
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if ((buf[buf.length - 1] & 0x7f) == 0) {
      // One exception: if there's more than one byte and the most
      // significant bit of the second-most-significant-byte is set
      // it would conflict with the sign bit. An example of this case
      // is +-255, which encode to 0xff00 and 0xff80 respectively.
      // (big-endian).
      if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) == 0) {
        throw new ScriptException(ScriptError.SCRIPT_ERR_NUMBER_MINENCODE, 'non-minimally encoded script number');
      }
    }
  }
  return fromSM(buf, endian: Endian.little);
}

List<int> toSM(BigInt value, {Endian endian = Endian.big}) {
  var buf = toSMBigEndian(value);

  if (endian == Endian.little) {
    buf = buf.reversed.toList();
  }
  return buf;
}

List<int> toSMBigEndian(BigInt value) {
  List<int> buf = [];
  if (value.compareTo(BigInt.zero) == -1) {
    buf = toBuffer(-value);
    if (buf[0] & 0x80 != 0) {
      buf = [0x80] + buf;
    } else {
      buf[0] = buf[0] | 0x80;
    }
  } else {
    buf = toBuffer(value);
    if (buf[0] & 0x80 != 0) {
      buf = [0x00] + buf;
    }
  }

  if (buf.length == 1 && buf[0] == 0) {
    buf = [];
  }
  return buf;
}

BigInt fromSM(List<int> buf, {Endian endian = Endian.big}) {
  BigInt ret;
  List<int> localBuffer = buf.toList();
  if (localBuffer.length == 0) {
    return decodeBigIntSV([0]);
  }

  if (endian == Endian.little) {
    localBuffer = buf.reversed.toList();
  }

  if (localBuffer[0] & 0x80 != 0) {
    localBuffer[0] = localBuffer[0] & 0x7f;
    ret = decodeBigIntSV(localBuffer);
    ret = (-ret);
  } else {
    ret = decodeBigIntSV(localBuffer);
  }

  return ret;
}

//FIXME: New implementation. Untested
List<int> toBuffer(BigInt value, {int size = 0, Endian endian = Endian.big}) {
  String hex;
  List<int> buf = [];
  if (size != 0) {
    hex = value.toRadixString(16);
    int natlen = (hex.length / 2) as int;
    buf = HEX.decode(hex);

    if (natlen == size) {
      // buf = buf
    } else if (natlen > size) {
      buf = buf.sublist(natlen - buf.length, buf.length);
//            buf = BN.trim(buf, natlen);
    } else if (natlen < size) {
      List<int> padding = <int>[size];
      padding.fillRange(0, size, 0);
      buf.insertAll(0, padding);
//            buf = BN.pad(buf, natlen, opts.size)
    }
  } else {
    hex = value.toRadixString(16);
    buf = HEX.decode(hex);
  }

  if (endian == Endian.little) {
    buf = buf.reversed.toList();
  }

  return buf;
}


/// Minimally encode the buffer content
///
/// (see https://github.com/bitcoincashorg/spec/blob/master/may-2018-reenabled-opcodes.md#op_bin2num)
List<int> minimallyEncode(List<int> buf) {
  if (buf.isEmpty) {
    return buf;
  }

  // If the last byte is not 0x00 or 0x80, we are minimally encoded.
  var last = buf[buf.length - 1];
  if (last & 0x7f != 0) {
    return buf;
  }

  // If the script is one byte long, then we have a zero, which encodes as an
  // empty array.
  if (buf.length == 1) {
    return <int>[];
  }

  // If the next byte has it sign bit set, then we are minimaly encoded.
  if (buf[buf.length - 2] & 0x80 != 0) {
    return buf;
  }

  // We are not minimally encoded, we need to figure out how much to trim.
  for (var i = buf.length - 1; i > 0; i--) {
    // We found a non zero byte, time to encode.
    if (buf[i - 1] != 0) {
      if (buf[i - 1] & 0x80 != 0) {
        // We found a byte with it sign bit set so we need one more
        // byte.
        buf[i++] = last;
      } else {
        // the sign bit is clear, we can use it.
        buf[i - 1] |= last;
      }

      return buf.sublist(0, i);
    }
  }

  // If we found the whole thing is zeros, then we have a zero.
  return <int>[];
}

/**
 * checks that LE encoded number is minimally represented.  That is that there are no leading zero bytes except in
 * the case: if there's more than one byte and the most significant bit of the second-most-significant-byte is set it
 * would conflict with the sign bit.
 * @param bytesLE
 * @return
 */
bool checkMinimallyEncoded(List<int> bytes, int maxNumSize) {
  if (bytes.length > maxNumSize) {
    return false;
  }

  if (bytes.length > 0) {
// Check that the number is encoded with the minimum possible number
// of bytes.
//
// If the most-significant-byte - excluding the sign bit - is zero
// then we're not minimal. Note how this test also rejects the
// negative-zero encoding, 0x80.
    if ((bytes[bytes.length - 1] & 0x7f) == 0) {
// One exception: if there's more than one byte and the most
// significant bit of the second-most-significant-byte is set it
// would conflict with the sign bit. An example of this case is
// +-255, which encode to 0xff00 and 0xff80 respectively.
// (big-endian).
      if (bytes.length <= 1 || (bytes[bytes.length - 2] & 0x80) == 0) {
        return false;
      }
    }
  }

  return true;
}

/** Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in little endian format. */
int readUint16(List<int> bytes, int offset) {
  return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
}

/** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format. */
int readUint32(List<int> bytes, int offset) {
  return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8) | ((bytes[offset + 2] & 0xff) << 16) | ((bytes[offset + 3] & 0xff) << 24);
}

int make_rshift_mask(int n) {
  var maskArray = [0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80];
  return maskArray[n];
}

int make_lshift_mask(int n) {
  var maskArray = [0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01];
  return maskArray[n];
}

List<int> RShift(List<int> x, int n) {
  int bit_shift = n % 8;
  int byte_shift = n ~/ 8;

  int mask = make_rshift_mask(bit_shift);
  int overflow_mask = ~mask;

  var result = List<int>.generate(x.length, (i) => 0);
  // valtype result(x.size(), 0x00);

  for (int i = 0; i < x.length; i++) {
    int k = i + byte_shift;
    if (k < x.length) {
      int val = (x[i] & mask);
      val >>= bit_shift;
      result[k] |= val;
    }

    if (k + 1 < x.length) {
      int carryval = (x[i] & overflow_mask);
      carryval <<= 8 - bit_shift;
      result[k + 1] |= carryval;
    }
  }
  return result;
}

// shift x left by n bits, implements OP_LSHIFT
List<int> LShift(List<int> x, int n) {
  int bit_shift = n % 8;
  int byte_shift = n ~/ 8;

  int mask = make_lshift_mask(bit_shift);
  int overflow_mask = ~mask;

  var result = List<int>.generate(x.length, (i) => 0);
  for (int index = x.length; index > 0; index--) {
    int i = index - 1;
// make sure that k is always >= 0
    if (byte_shift <= i) {
      int k = i - byte_shift;
      int val = (x[i] & mask);
      val <<= bit_shift;
      result[k] |= val;

      if (k >= 1) {
        int carryval = (x[i] & overflow_mask);
        carryval >>= 8 - bit_shift;
        result[k - 1] |= carryval;
      }
    }
  }
  return result;
}
