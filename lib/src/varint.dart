import 'dart:typed_data';

import 'package:buffer/buffer.dart';

class VarInt {
  /** @deprecated use {{@link #intValue()} or {{@link #longValue()}}} */
  int value = 0;
  int originallyEncodedSize = 0;

  /**
   * Constructs a new VarInt with the given unsigned long value.
   *
   * @param value the unsigned long value (beware widening conversion of negatives!)
   */
  VarInt.fromInt(this.value) {
    this.value = value;
    originallyEncodedSize = getSizeInBytes();
  }

  /**
   * Constructs a new VarInt with the value parsed from the specified offset of the given buffer.
   *
   * @param buf the buffer containing the value
   * @param offset the offset of the value
   */
  VarInt.fromBuffer(List<int> buf, int offset) {
    var reader = ByteDataReader();
    reader.add(buf);
    int first = 0xFF & buf[offset];
    if (first < 253) {
      value = first;
      originallyEncodedSize = 1; // 1 data byte (8 bits)
    } else if (first == 253) {
      value = reader.readUint16(Endian.little); //Utils.readUint16(buf, offset + 1);
      originallyEncodedSize = 3; // 1 marker + 2 data bytes (16 bits)
    } else if (first == 254) {
      value = reader.readUint32(Endian.little); //Utils.readUint32(buf, offset + 1);
      originallyEncodedSize = 5; // 1 marker + 4 data bytes (32 bits)
    } else {
      value = reader.readInt64(Endian.little); // Utils.readInt64(buf, offset + 1);
      originallyEncodedSize = 9; // 1 marker + 8 data bytes (64 bits)
    }
  }

  static VarInt fromStream(ByteDataReader stream) {
    int first = 0xFF & stream.readUint8();
    int value;
    if (first < 253) {
      value = first;
    } else if (first == 253) {
      value = stream.readUint16(Endian.little); //Utils.readUint16FromStream(stream);
    } else if (first == 254) {
      value = stream.readUint32(Endian.little); //Utils.readUint32FromStream(stream);
    } else {
      value = stream.readInt64(Endian.little); //Utils.readInt64FromStream(stream);
    }

    return VarInt.fromInt(value);
  }

  int intValue() {
    return value;
  }

  /**
   * Returns the original number of bytes used to encode the value if it was
   * deserialized from a byte array, or the minimum encoded size if it was not.
   */
  int getOriginalSizeInBytes() {
    return originallyEncodedSize;
  }

  /**
   * Returns the minimum encoded size of the value.
   */
  int getSizeInBytes() {
    return sizeOf(value);
  }

  /**
   * Returns the minimum encoded size of the given unsigned long value.
   *
   * @param value the unsigned long value (beware widening conversion of negatives!)
   */
  static int sizeOf(int value) {
    // if negative, it's actually a very large unsigned long value
    if (value < 0) return 9; // 1 marker + 8 data bytes
    if (value < 253) return 1; // 1 data byte
    if (value <= 0xFFFF) return 3; // 1 marker + 2 data bytes
    if (value <= 0xFFFFFFFF) return 5; // 1 marker + 4 data bytes
    return 9; // 1 marker + 8 data bytes
  }

  /**
   * Encodes the value into its minimal representation.
   *
   * @return the minimal encoded bytes of the value
   */
  List<int> encode() {
    List<int> bytes;
    switch (sizeOf(value)) {
      case 1:
        return [value];
      case 3:
        var writer = ByteDataWriter();
        writer.write([253]);
        writer.writeUint16(value, Endian.little);
        return writer.toBytes().toList();
      case 5:
        var writer = ByteDataWriter();
        writer.write([253]);
        writer.writeUint32(value, Endian.little);
        return writer.toBytes().toList();
      default:
        var writer = ByteDataWriter();
        writer.write([255]);
        writer.writeInt64(value, Endian.little);
        return writer.toBytes().toList();
    }
  }
}
