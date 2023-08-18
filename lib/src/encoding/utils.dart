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

// Uint8List varIntWriter(int? length) {
//     ByteDataWriter writer = ByteDataWriter();
//
//     if (length == null) {
//         return writer.toBytes();
//     }
//
//     if (length < 0xFD) {
//         writer.writeUint8(length);
//         return writer.toBytes();
//     }
//
//     if (length < 0xFFFF) {
// //            return HEX.decode("FD" + length.toRadixString(16));
//         writer.writeUint8(253);
//         writer.writeUint16(length, Endian.little);
//         return writer.toBytes();
//     }
//
//     if (length < 0xFFFFFFFF) {
// //            return HEX.decode("FE" + length.toRadixString(16));
//
//         writer.writeUint8(254);
//         writer.writeUint32(length, Endian.little);
//         return writer.toBytes();
//     }
//
//     if (BigInt.parse("0xFFFFFFFFFFFFFFFF").compareTo(BigInt.from(length)) == -1) {
// //            return HEX.decode("FF" + length.toRadixString(16));
//
//         writer.writeUint8(255);
//         writer.writeInt32(length & -1, Endian.little);
//         writer.writeUint32((length / 0x100000000).floor(), Endian.little);
//         return writer.toBytes();
//     }
//
//     return writer.toBytes();
// }

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


//Implementation from bsv lib
int readVarIntNum(ByteDataReader reader){
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
                throw new Exception('number too large to retain precision - use readVarintBN');
            }
            break;
        default:
            return first;
    }
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


toScriptNumBuffer(BigInt value) {
    return toSM(value, endian: Endian.little);
}


BigInt fromScriptNumBuffer(Uint8List buf, bool fRequireMinimal, {int nMaxNumSize = 4}) {
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


toSM(BigInt value, {Endian endian = Endian.big}) {
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


