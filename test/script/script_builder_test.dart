import 'dart:ffi';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_chunk.dart';
import 'package:test/test.dart';

main() {
  test('creates smallest pushdata instruction ', () {
    for (int i = -100; i <= 100; i++) {
      SVScript s = ScriptBuilder().number(i).build();
      for (ScriptChunk ch in s.chunks) {
        ch.checkMinimalPush(0);
      }
    }
  });

  test('0 should encode directly to 0', () {
    // Test encoding of zero, which should result in an opcode
    var builder = ScriptBuilder();

    // 0 should encode directly to 0
    builder.number(0);
    var nullList = Uint8List(1);
    nullList[0] = 0;
    expect(nullList, orderedEquals(builder
        .build()
        .buffer));
  });

  test('properly encodes positive number', () {
    var builder = ScriptBuilder();

    builder.number(5);
    var list = Uint8List(1);
    list[0] = 0x55;
    expect(list, orderedEquals(builder
        .build()
        .buffer));
  });

  test('properly encodes large numbers', () {
    var builder = new ScriptBuilder();
    // 21066 should take up three bytes including the length byte
    // at the start

    builder.number(0x524a);
    List<int> list = [
      0x02, // Length of the pushed data
      0x4a, 0x52 // Pushed data
    ];

    expect(
        list,
        orderedEquals(
            builder
                .build()
                .buffer)); // }, builder.build().getProgram());

    // Test the trimming code ignores zeroes in the middle
    builder = ScriptBuilder();
    builder.number(0x110011);
    expect(4, equals(builder
        .build()
        .buffer
        .length));

    // Check encoding of a value where signed/unsigned encoding differs
    // because the most significant byte is 0x80, and therefore a
    // sign byte has to be added to the end for the signed encoding.
    builder = ScriptBuilder();
    builder.number(0x8000);
    expect([
      0x03, // Length of the pushed data
      0x00, 0x80, 0x00 // Pushed data
    ], orderedEquals(builder
        .build()
        .buffer));
  });

  test('properly encodes negative numbers', () {
    // Check encoding of a negative value
    var builder = new ScriptBuilder();
    builder.number(-5);
    expect([
      0x01, // Length of the pushed data
      133 // Pushed data
    ], orderedEquals(builder
        .build()
        .buffer));
  });

  test('encodes numbers > 16 using pushdata', () {
    var builder = new ScriptBuilder();
    // Numbers greater than 16 must be encoded with PUSHDATA
    builder.number(15).number(16).number(17);
    builder.numberAtIndex(0, 17).numberAtIndex(1, 16).numberAtIndex(2, 15);
    var script = builder.build();
    expect(
        "11 OP_16 OP_15 OP_15 OP_16 11", equals(script.toString(type: 'asm')));
  });

  test('can encode OP_TRUE', () {
    var expected = [OpCodes.OP_TRUE];
    var s = new ScriptBuilder().opTrue().build().buffer;
    expect( s, orderedEquals(expected));
  });

  test('can encode OP_FALSE', (){
    var expected = [OpCodes.OP_FALSE];
    var s = new ScriptBuilder().opFalse().build().buffer;
    expect( s, orderedEquals(expected));
  });
}
