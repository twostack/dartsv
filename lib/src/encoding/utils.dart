import 'package:hex/hex.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'dart:typed_data';

List<int> sha256Twice(List<int> bytes) {

    var first = new SHA256Digest().process(Uint8List.fromList(bytes));
    var second = new SHA256Digest().process(first);
    return second.toList();

}

List<int> sha256(List<int> bytes){
   return new SHA256Digest().process(Uint8List.fromList(bytes)).toList();
}

List<int> hash160(List<int> bytes){
    List<int> shaHash = new SHA256Digest().process(Uint8List.fromList(bytes));
    var ripeHash = new RIPEMD160Digest().process(shaHash);
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

