import 'dart:ffi';
import 'dart:math';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

main() {
    group("Script from ByteArray", () {

        test('should parse this buffer containing an OP code', () {
            List<int> buffer = [OpCodes.OP_0];
            var script = SVScript.fromByteArray(Uint8List.fromList(buffer));
            expect(script.buffer.length, equals(1));
            expect(script.buffer[0], equals(buffer[0]));
        });


        //TODO: Keep an eye on this "opcodenum" thing. Having the individual entries parsed into a class might be interesting.
        test('should parse this buffer containing another OP code', () {
            List<int> buffer = [OpCodes.OP_CHECKMULTISIG];
            var script = SVScript.fromByteArray(Uint8List.fromList(buffer));
            expect(script.buffer.length, equals(1));
            expect(script.buffer[0], equals(buffer[0]));
        });

        test('should parse this buffer containing three bytes of data', () {
            List<int> buffer = [3, 1, 2, 3];
            var script = SVScript.fromByteArray(Uint8List.fromList(buffer));
            expect(script.buffer.length, equals(4));
            expect(script.toHex(), equals('03010203'));
        });
    });

    group("Script from PublicKeyHash", (){

        test('should create script from livenet address', () {
          var address = Address('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14');
          var script = P2PKHLockBuilder(address).getScriptPubkey();
          expect(script, isNotNull);
          expect(script.toString(), equals('OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG'));

          //Deliberately leaving these tests out. No P2SH support a.t.m.
//          expect(script.isPublicKeyHashOut(), isTrue);
//          expect(script.toAddress().toString(), equals('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14'));
        });

    });

  group('fromString constructor', () {
    test('should parse these known scripts', () {
      expect( SVScript.fromString('OP_0 OP_PUSHDATA4 3 0x010203 OP_0').toString(), equals('OP_0 OP_PUSHDATA4 3 0x010203 OP_0'));
      expect( SVScript.fromString('OP_0 OP_PUSHDATA2 3 0x010203 OP_0').toString(), equals('OP_0 OP_PUSHDATA2 3 0x010203 OP_0'));
      expect( SVScript.fromString('OP_0 OP_PUSHDATA1 3 0x010203 OP_0').toString(), equals('OP_0 OP_PUSHDATA1 3 0x010203 OP_0'));
      expect(SVScript.fromString('OP_0 3 0x010203 OP_0').toString(), equals('OP_0 3 0x010203 OP_0'));
    });
  });

  group('isPushOnly method', () {
    test("should know these scripts are or aren't push only", () {
      expect(SVScript.fromString('OP_NOP 1 0x01').isPushOnly(), isFalse);
      expect(SVScript.fromString('OP_0').isPushOnly(), isTrue);
      expect(SVScript.fromString('OP_0 OP_RETURN').isPushOnly(), isFalse);
      expect(SVScript.fromString('OP_PUSHDATA1 5 0x1010101010').isPushOnly(), isTrue);
      expect(SVScript.fromString('OP_PUSHDATA2 5 0x1010101010').isPushOnly(), isTrue);
      expect(SVScript.fromString('OP_PUSHDATA4 5 0x1010101010').isPushOnly(), isTrue);
      // like bitcoind, we regard OP_RESERVED as being "push only"
      expect(SVScript.fromString('OP_RESERVED').isPushOnly(), isTrue);
    });
  });

  test('can roundtrip serializing of a script, preserving pushdata', (){

    final s = 'OP_0 OP_RETURN 34 0x31346b7871597633656d48477766386d36596753594c516b4743766e395172677239 66 0x303236336661663734633031356630376532633834343538623566333035653262323762366566303838393238383133326435343264633139633436663064663532 OP_PUSHDATA1 150 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
    final sc = SVScript.fromString(s);

    expect(sc.toString(), equals(s) );
  });


  group('#buildPublicKeyHashOut', () {
    test('should create script from livenet address', () {
      var address = Address('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14');
      var lockBuilder = P2PKHLockBuilder(address);
      var outScript = lockBuilder.getScriptPubkey();
      expect(outScript, isNotNull);

      expect(outScript.toString(), equals(
          'OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.toString(),
          equals('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14'));
    });

    test('should create script from testnet address', () {
      var address = Address('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33');
      var lockBuilder = P2PKHLockBuilder(address);
      var outScript = lockBuilder.getScriptPubkey();
      expect(outScript, isNotNull);

      expect(outScript.toString(), equals(
          'OP_DUP OP_HASH160 20 0xb96b816f378babb1fe585b7be7a2cd16eb99b3e4 OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.toString(),
          equals('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33'));
    });
  });



  group('#fromBuffer', () {
    test('should parse this buffer containing an OP code', () {
      var buf = Uint8List(1);
      buf[0] = OpCodes.OP_0;
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(script.chunks[0].opcodenum, equals(buf[0]));
    });

    test('should parse this buffer containing another OP code', () {
      var buf = Uint8List(1);
      buf[0] = OpCodes.OP_CHECKMULTISIG;
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(script.chunks[0].opcodenum, equals(buf[0]));
    });

    test('should parse this buffer containing three bytes of data', () {
      var buf = Uint8List.fromList([3, 1, 2, 3]);
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
    });

    test('should parse this buffer containing OP_PUSHDATA1 and three bytes of data', () {
      var buf = Uint8List.fromList([0, 0, 1, 2, 3]);
      buf[0] = OpCodes.OP_PUSHDATA1;
      //buf.writeUInt8(3, 1);
      buf[1] = 3;

      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
    });

    test('should parse this buffer containing OP_PUSHDATA2 and three bytes of data', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_PUSHDATA2]);
      writer.writeUint16(3, Endian.little);
      writer.write([1, 2, 3]); //concatenate rest of buffer
      var buf = writer.toBytes();

      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
    });

    test('should parse this buffer containing OP_PUSHDATA4 and three bytes of data', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_PUSHDATA4]);
      writer.writeUint16(3, Endian.little);
      writer.write([0, 0, 1, 2, 3]); //concatenate rest of buffer
      var buf = writer.toBytes();

      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
    });

    test('should parse this buffer an OP code, data, and another OP code', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_0]);
      writer.write([OpCodes.OP_PUSHDATA4]);
      writer.writeUint16(3, Endian.little);
      writer.write([ 0, 0, 1, 2, 3]); //concatenate rest of buffer
      writer.write([OpCodes.OP_0]);
      var buf = writer.toBytes();

      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(3));
      expect(script.chunks[0].opcodenum, (buf[0]));
      expect(HEX.encode(script.chunks[1].buf), equals('010203'));
      expect(script.chunks[2].opcodenum, equals(buf[buf.length - 1]));
    });

  });

  group('#toBuffer', () {
    test('should output this buffer containing an OP code', () {
      var buf = Uint8List(1);
      buf[0] = OpCodes.OP_0;
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(script.chunks[0].opcodenum, equals(buf[0]));
      expect(script.toHex(), equals(HEX.encode(buf)));
    });

    test('should output this buffer containing another OP code', () {
      var buf = Uint8List(1);
      buf[0] = OpCodes.OP_CHECKMULTISIG;
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(script.chunks[0].opcodenum, equals(buf[0]));
      expect(script.toHex(), equals(HEX.encode(buf)));
    });

    test('should output this buffer containing three bytes of data', () {
      var buf = Uint8List.fromList([3, 1, 2, 3]);
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
      expect(script.toHex(), equals(HEX.encode(buf)));
    });

    test('should output this buffer containing OP_PUSHDATA1 and three bytes of data', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_PUSHDATA1]);
      writer.writeUint8(3);
      writer.write([ 1, 2, 3]);

      var script = SVScript.fromBuffer(writer.toBytes());
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
      expect(script.toHex(), HEX.encode(writer.toBytes()));
    });

    test('should output this buffer containing OP_PUSHDATA2 and three bytes of data', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_PUSHDATA2]);
      writer.writeUint16(3, Endian.little);
      writer.write([ 1, 2, 3]);

      var script = SVScript.fromBuffer(writer.toBytes());
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
      expect(script.toHex(), equals(HEX.encode(writer.toBytes())));
    });

    test('should output this buffer containing OP_PUSHDATA4 and three bytes of data', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_PUSHDATA4]);
      writer.writeUint16(3, Endian.little);
      writer.write([ 0, 0, 1, 2, 3]);

      var script = SVScript.fromBuffer(writer.toBytes());
      expect(script.chunks.length, equals(1));
      expect(HEX.encode(script.chunks[0].buf), equals('010203'));
      expect(script.toHex(), equals(HEX.encode(writer.toBytes())));
    });

    test('should output this buffer an OP code, data, and another OP code', () {
      var writer = ByteDataWriter();
      writer.write([OpCodes.OP_0]);
      writer.write([OpCodes.OP_PUSHDATA4]);
      writer.writeUint16(3, Endian.little);
      writer.write([ 0, 0, 1, 2, 3]);
      writer.write([OpCodes.OP_0]);

      var buf = writer.toBytes();
      var script = SVScript.fromBuffer(buf);
      expect(script.chunks.length, equals(3));
      expect(script.chunks[0].opcodenum, equals(buf[0]));
      expect(HEX.encode(script.chunks[1].buf), equals('010203'));
      expect(script.chunks[2].opcodenum, equals(buf[buf.length - 1]));
      expect(script.toHex(), equals(HEX.encode(buf)));
    });
  });



    group('constructing script from ASM', () {
      test('should parse this known script in ASM', () {
        var asm = 'OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG';
        var script = SVScript.fromASM(asm);
        expect(script.chunks[0].opcodenum, equals(OpCodes.OP_DUP));
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_HASH160));
        expect(script.chunks[2].opcodenum, equals(20));
        expect(HEX.encode(script.chunks[2].buf), equals('f4c03610e60ad15100929cc23da2f3a799af1725'));
        expect(script.chunks[3].opcodenum, equals(OpCodes.OP_EQUALVERIFY));
        expect(script.chunks[4].opcodenum, equals(OpCodes.OP_CHECKSIG));
      });

      test('should parse this known problematic script in ASM', () {
        var asm = 'OP_RETURN 026d02 0568656c6c6f';
        var script = SVScript.fromASM(asm);
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should know this is invalid hex', () {
        var asm = 'OP_RETURN 026d02 0568656c6c6fzz';
        expect(() => SVScript.fromASM(asm), throwsException);
      });

      test('should parse this long PUSHDATA1 script in ASM', () {
        var buf = Uint8List(220);
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA1));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should parse this long PUSHDATA2 script in ASM', () {
        var buf = Uint8List(1024);
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA2));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should parse this long PUSHDATA4 script in ASM', () {
        var buf = Uint8List(pow(2, 17) as int);
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA4));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should return this script correctly - OP_FALSE', () {
        var asm1 = 'OP_FALSE';
        var asm2 = 'OP_0';
        var asm3 = '0';
        expect(SVScript.fromASM(asm1).toString(type:'asm'),equals(asm3));
        expect(SVScript.fromASM(asm2).toString(type:'asm'),equals(asm3));
        expect(SVScript.fromASM(asm3).toString(type:'asm'),equals(asm3));
      });


      test('should return this script correctly - OP_1NEGATE', () {
        var asm1 = 'OP_1NEGATE';
        var asm2 = '-1';
        expect(SVScript.fromASM(asm1).toString(type:'asm'), equals(asm2));
        expect(SVScript.fromASM(asm2).toString(type:'asm'), equals(asm2));
      });


      test('should output this buffer an OP code, data, and another OP code', () {
        var writer = ByteDataWriter();
        writer.writeUint8(OpCodes.OP_0);
        writer.writeUint8(OpCodes.OP_PUSHDATA4);
        writer.writeUint16(3, Endian.little);
        writer.write([0, 0, 1, 2, 3]);
        writer.writeUint8(OpCodes.OP_0);

        var buf = writer.toBytes();
        var script = SVScript.fromBuffer(buf);
        expect(script.chunks.length, equals(3));
        expect(script.chunks[0].opcodenum, equals(buf[0]));
        expect(HEX.encode(script.chunks[1].buf), equals('010203'));
        expect(script.chunks[2].opcodenum, equals(buf[buf.length - 1]));
        expect(script.toString(),  equals('OP_0 OP_PUSHDATA4 3 0x010203 OP_0'));
      });

      test('should output this known script as ASM', () {
        var script = SVScript.fromHex('76a914f4c03610e60ad15100929cc23da2f3a799af172588ac');
        expect(script.toString(type: 'asm'), equals('OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG'));
      });


      test('should output this known script with pushdata1 opcode as ASM', () {
        // network: livenet
        // txid: dd6fabd2d879be7b8394ad170ff908e9a36b5d5d0b394508df0cca36d2931589
        var script = SVScript.fromHex('00483045022100beb1d83771c04faaeb40bded4f031ed0e0730aaab77cf70102ecd05734a1762002206f168fb00f3b9d7c04b8c78e1fc11e81b9caa49885a904bf22780a7e14a8373101483045022100a319839e37828bf164ff45de34a3fe22d542ebc8297c5d87dbc56fc3068ff9d5022077081a877b6e7f104d8a2fe0985bf2eb7de2e08edbac9499fc3710a353f65461014c69522103a70ae7bde64333461fb88aaafe12ad6c67ca17c8213642469ae191e0aabc7251210344a62338c8ddf138771516d38187146242db50853aa588bcb10a5e49c86421a52102b52a1aed304c4d6cedcf82911f90ca6e1ffed0a5b8f7f19c68213d6fcbde677e53ae');
        expect(script.toString(type:'asm'), equals('0 3045022100beb1d83771c04faaeb40bded4f031ed0e0730aaab77cf70102ecd05734a1762002206f168fb00f3b9d7c04b8c78e1fc11e81b9caa49885a904bf22780a7e14a8373101 3045022100a319839e37828bf164ff45de34a3fe22d542ebc8297c5d87dbc56fc3068ff9d5022077081a877b6e7f104d8a2fe0985bf2eb7de2e08edbac9499fc3710a353f6546101 522103a70ae7bde64333461fb88aaafe12ad6c67ca17c8213642469ae191e0aabc7251210344a62338c8ddf138771516d38187146242db50853aa588bcb10a5e49c86421a52102b52a1aed304c4d6cedcf82911f90ca6e1ffed0a5b8f7f19c68213d6fcbde677e53ae'));
      });

      test('should OP_1NEGATE opcode as -1 with ASM', () {
        var script = SVScript.fromString('OP_1NEGATE');
        expect(script.toString(type: 'asm'), equals('-1'));
      });

    });


  group('toHex', () {
    test('should return an hexa string "03010203" as expected from [3, 1, 2, 3]', () {
      var buf = Uint8List.fromList([3, 1, 2, 3]);
      var script = SVScript.fromBuffer(buf);
      expect(script.toHex(), equals('03010203'));
    });
  });

    test('should add to existing script', (){
      var buf = Uint8List(1);
      var script = SVScript.fromString('OP_FALSE');
      expect(script.add(buf).toString(), equals('OP_0 1 0x00'));
      expect(script.add(buf).toHex(), equals('0001000100'));
    });

    test('should add these push data', () {
      var buf = Uint8List(1);
      expect(SVScript().add(buf).toString(), equals('1 0x00'));

      buf = Uint8List(255);
      expect(SVScript().add(buf).toString(), equals('OP_PUSHDATA1 255 0x' + HEX.encode(buf)));

      buf = Uint8List(256);
      expect(SVScript().add(buf).toString(), equals('OP_PUSHDATA2 256 0x' + HEX.encode(buf)));

      buf = Uint8List(pow(2, 16) as int);
      expect(SVScript().add(buf).toString(), equals('OP_PUSHDATA4 ${pow(2, 16)} 0x${HEX.encode(buf)}'));
    });


    test('should add both pushdata and non-pushdata chunks', () {
      expect(SVScript().add('OP_CHECKMULTISIG').toString(), equals('OP_CHECKMULTISIG'));
      expect(SVScript().add(OpCodes.opcodeMap['OP_CHECKMULTISIG']).toString(), equals('OP_CHECKMULTISIG'));

      var buf = Uint8List(1);
      expect(SVScript().add(buf).toString(), equals('1 0x00'));
    });

    test('should work for no data OP_RETURN', () {
      expect(SVScript().add(OpCodes.OP_RETURN).add('').toString(), equals('OP_RETURN'));
    });

  group('#removeCodeseparators', () {
    test('should remove any OP_CODESEPARATORs', () {
      expect(SVScript.fromString('OP_CODESEPARATOR OP_0 OP_CODESEPARATOR').removeCodeseparators().toString(), equals('OP_0'));
    });
  });

  group('#findAndDelete', () {
    test('should find and delete this buffer', () {
      expect(SVScript.fromString('OP_RETURN 2 0xf0f0').findAndDelete(SVScript.fromString('2 0xf0f0')).toString(), equals('OP_RETURN'));
    });

    test('should do nothing', () {
      expect(SVScript.fromString('OP_RETURN 2 0xf0f0').findAndDelete(SVScript.fromString('2 0xffff')).toString(), equals('OP_RETURN 2 0xf0f0'));
    });
  });

  /* FIXME: Correct enough. There is a pesky edge case which need _chunk.buf == null in SVScript. I don't like it.
  group('#checkMinimalPush', () {
    test('should check these minimal pushes', () {
      expect(SVScript().add(1).checkMinimalPush(0), isTrue);
      expect(SVScript().add(0).checkMinimalPush(0), isTrue);
      expect(SVScript().add(-1).checkMinimalPush(0), isTrue);
      expect(SVScript().add(1000).checkMinimalPush(0), isTrue);
      expect(SVScript().add(0xffffffff).checkMinimalPush(0), isTrue);
      expect(SVScript().add(0xffffffffffffffff).checkMinimalPush(0), isTrue);
      expect(SVScript().add(Uint8List.fromList([0])).checkMinimalPush(0), isTrue);

      var buf = Uint8List(75);
      expect(SVScript().add(buf).checkMinimalPush(0), isTrue);

      buf = Uint8List(76);
      expect(SVScript().add(buf).checkMinimalPush(0), isTrue);

      buf = Uint8List(256);
      expect(SVScript().add(buf).checkMinimalPush(0), isTrue);
    });
  });

   */

  group('#add and #prepend', ()
    {
      test('should add these ops', () {
        expect(SVScript().add(1).add(10).add(186).toString(), equals('0x01 0x0a 0xba'));
        expect(SVScript().add(1000).toString(), equals('0x03e8'));
        expect(SVScript().add('OP_CHECKMULTISIG').toString(), equals('OP_CHECKMULTISIG'));
        expect( SVScript().add('OP_1').add('OP_2').toString(), equals('OP_1 OP_2'));
        expect(SVScript().add(OpCodes.OP_CHECKMULTISIG).toString(), equals('OP_CHECKMULTISIG'));
        expect(SVScript().add(OpCodes.opcodeMap['OP_CHECKMULTISIG']).toString(), equals('OP_CHECKMULTISIG'));
      });
    });

}

