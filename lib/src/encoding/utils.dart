import 'package:dartsv/src/exceptions.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';
import 'dart:math';

//import 'package:pointycastle/src/utils.dart';
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

List<int> varintBufNum(n) {
//    List<int> buf ;
  ByteDataWriter writer = ByteDataWriter();
  if (n < 253) {
    writer.writeUint8(n);
  } else if (n < 0x10000) {
    writer.writeUint8(253);
    writer.writeUint16(n, Endian.little);
  } else if (n < 0x100000000) {
    writer.writeUint8(254);
    writer.writeUint32(n, Endian.little);
  } else {
    writer.writeUint8(255);
    writer.writeInt32(n & -1, Endian.little);
    writer.writeUint32((n / 0x100000000).floor(), Endian.little);
  }
  return writer.toBytes().toList();
}

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

List<int> calcVarInt(int? length) {
  if (length == null) return Uint8List(0);

  if (length < 0xFD) return HEX.decode(length.toRadixString(16));

  if (length < 0xFFFF) return HEX.decode("FD" + length.toRadixString(16));

  if (length < 0xFFFFFFFF) return HEX.decode("FE" + length.toRadixString(16));

  if (BigInt.parse("0xFFFFFFFFFFFFFFFF").compareTo(BigInt.from(length)) == -1)
    return HEX.decode("FF" + length.toRadixString(16));

  return Uint8List(0);
}

//Implementation from bsv lib
int readVarIntNum(ByteDataReader reader) {
  var first = reader.readUint8();
  switch (first) {
    case 0xFD:
      return reader.readUint16(Endian.little);
      break;
    case 0xFE:
      return reader.readUint32(Endian.little);
      break;
    case 0xFF:
      var bn = BigInt.from(reader.readUint64(Endian.little));
      var n = bn.toInt();
      if (n <= pow(2, 53)) {
        return n;
      } else {
        throw new Exception(
            'number too large to retain precision - use readVarintBN');
      }
      break;
    default:
      return first;
  }
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

int? getBufferOffset(int count) {
  if (count < 0xFD) return 1;

  if (count == 0xFD) return 3; //2 bytes ==  Uint16

  if (count == 0xFE) return 5; //4 bytes == Uint32

  if (count == 0xFF) return 9;
}

/// Decode a BigInt from bytes in big-endian encoding.
BigInt decodeBigInt(List<int> bytes) {
  BigInt result = new BigInt.from(0);

  for (int i = 0; i < bytes.length; i++) {
    result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }

  return result;
}

var _byteMask = new BigInt.from(0xff);

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List encodeBigInt(BigInt number) {
  int size = (number.bitLength + 7) >> 3;

  var result = Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }

  return result;
}

List<int> castToBuffer(BigInt value) {
  return toSM(value, endian: Endian.little);
}

BigInt castToBigInt(Uint8List buf, bool fRequireMinimal,
    {int nMaxNumSize = 4}) {
  if (!(buf.length <= nMaxNumSize)) {
    throw new ScriptException('script number overflow');
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
        throw new Exception('non-minimally encoded script number');
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

BigInt fromSM(Uint8List buf, {Endian endian = Endian.big}) {
  BigInt ret;
  List<int> localBuffer = buf.toList();
  if (localBuffer.length == 0) {
    return decodeBigInt([0]);
  }

  if (endian == Endian.little) {
    localBuffer = buf.reversed.toList();
  }

  if (localBuffer[0] & 0x80 != 0) {
    localBuffer[0] = localBuffer[0] & 0x7f;
    ret = decodeBigInt(localBuffer);
    ret = (-ret);
  } else {
    ret = decodeBigInt(localBuffer);
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

/**
 * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
 * a 4 byte big endian length field, followed by the stated number of bytes representing
 * the number in big endian format (with a sign bit).
 * @param hasLength can be set to false if the given array is missing the 4 byte length field
 */
BigInt decodeMPI(Uint8List mpi, bool hasLength) {
  ByteDataReader reader = ByteDataReader()..add(mpi);
  Uint8List buf;
  if (hasLength) {
    int length = reader.readUint32(Endian.big);
    buf = Uint8List(length);
// arraycopy(mpi, 4, buf, 0, length);
    buf.setRange(0, length, mpi.getRange(4, length));
  } else
    buf = mpi;
  if (buf.length == 0) return BigInt.zero;
  bool isNegative = (buf[0] & 0x80) == 0x80;
  if (isNegative) buf[0] &= 0x7f;
  BigInt result = castToBigInt(buf, false);
  return isNegative ? -result : result;
}

/**
 * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
 * a 4 byte big endian length field, followed by the stated number of bytes representing
 * the number in big endian format (with a sign bit).
 * @param includeLength indicates whether the 4 byte length field should be included
 */
Uint8List encodeMPI(BigInt value, bool includeLength) {
  if (value == BigInt.zero) {
    if (!includeLength)
      return Uint8List.fromList([]);
    else
      return Uint8List.fromList([0x00, 0x00, 0x00, 0x00]);
  }
  bool isNegative = value.isNegative;
  if (isNegative) value = -value;
  Uint8List array = Uint8List.fromList(castToBuffer(value));
  int length = array.length;
  if ((array[0] & 0x80) == 0x80) length++;
  if (includeLength) {
    Uint8List result = Uint8List(length + 4);
// System.arraycopy(array, 0, result, length - array.length + 3, array.length);
    result.setRange(0, array.length,
        array.getRange(length - array.length + 3, array.length));
// buf.setRange(0, length, mpi.getRange(4, length));
//     uint32ToByteArrayBE(length, result, 0);
    var writer = ByteDataWriter();
    writer.writeUint32(length, Endian.big);
    result = writer.toBytes();

    if (isNegative) result[4] |= 0x80;
    return result;
  } else {
    Uint8List result;
    if (length != array.length) {
      result = Uint8List(length);
      result.setRange(0, array.length, array, 1);
      // System.arraycopy(array, 0, result, 1, array.length);

    } else
      result = array;
    if (isNegative) result[0] |= 0x80;
    return result;
  }
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
int readUint16(Uint8List bytes, int offset) {
  return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
}

/** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format. */
int readUint32(Uint8List bytes, int offset) {
  return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8) | ((bytes[offset + 2] & 0xff) << 16) | ((bytes[offset + 3] & 0xff) << 24);
}
