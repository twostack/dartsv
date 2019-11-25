import 'package:hex/hex.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'dart:typed_data';

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
    var ripeHash = new RIPEMD160Digest().process(shaHash);
    return ripeHash.toList();
}


List<int> ripemd160(List<int> bytes) {
    var ripeHash = new RIPEMD160Digest().process(bytes);
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


List<int> calcVarInt(int length) {
    if (length == null)
        return Uint8List(0);

    if (length < 0xFD) return HEX.decode(length.toRadixString(16));

    if (length < 0xFFFF) return HEX.decode("FD" + length.toRadixString(16));

    if (length < 0xFFFFFFFF) return HEX.decode("FE" + length.toRadixString(16));

    if (length < 0xFFFFFFFFFFFFFFFF) return HEX.decode("FF" + length.toRadixString(16));

    return Uint8List(0);
}


//FIXME: Should probably have two versions of this function. One for BigInt, one for Int
BigInt readVarInt(Uint8List buffer) {
    var first = int.parse(HEX.encode(buffer.sublist(0, 1)), radix: 16).toUnsigned(8);

    switch (first) {
        case 0xFD :
            return BigInt.from(hexToUint16(buffer.sublist(1, 3))); //2 bytes ==  Uint16

        case 0xFE :
            return BigInt.from(hexToUint32(buffer.sublist(1, 5))); //4 bytes == Uint32

        case 0xFF :
            return hexToUint64(buffer.sublist(1, 9)); //8 bytes == Uint64

        default :
            return BigInt.from(first);
    }
}

int getBufferOffset(int count) {
    if (count < 0xFD)
        return 1;

    if (count == 0xFD)
        return 3; //2 bytes ==  Uint16

    if (count == 0xFE)
        return 5; //4 bytes == Uint32

    if (count == 0xFF)
        return 9;
}


/*
BigInt encoding is taken from PointyCastle implementation and adapted to cater
for negative numbers
 */

/// Decode a BigInt from bytes in big-endian encoding.
BigInt decodeBigInt(List<int> bytes) {
    BigInt result = new BigInt.from(0);
    bool isNegative = false;

    //if leading byte is 0x80 we assume a negative number
    if (bytes.length > 0 && (bytes[0] ^ 0x80 == 0)){
        bytes.removeAt(0); //drop first byte
        isNegative = true;
    }

    for (int i = 0; i < bytes.length; i++) {
        result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
    }

    if (isNegative){
        return -result;
    }else {
        return result;
    }
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

    //if number is negative, then we prepend a byte with the high bit set
    if (number.isNegative){
        var tmpList = result.toList();
        tmpList.insert(0, 1 | 0x80);
        return Uint8List.fromList(tmpList);
    }

    return result;
}


toScriptNumBuffer (BigInt value){
    return toSM(value, endian: Endian.little);
}


BigInt fromScriptNumBuffer(Uint8List buf, bool fRequireMinimal, {int nMaxNumSize = 4}) {
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

List<int> toSMBigEndian(BigInt value){

    List<int> buf = [];
    if (value.compareTo(BigInt.zero) == -1) {
        buf = encodeBigInt(-value);
        if (buf[0] & 0x80 != 0) {
            buf = [0x80] + buf;
        } else {
            buf[0] = buf[0] | 0x80;
        }
    } else {
        buf = encodeBigInt(value);
        if (buf[0] & 0x80 != 0) {
            buf = [0x00] + buf;
        }
    }

    if (buf.length == 1 && buf[0] == 0) {
        buf = [];
    }
    return buf;
}


BigInt fromSM (Uint8List buf, {Endian endian = Endian.big}) {
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

