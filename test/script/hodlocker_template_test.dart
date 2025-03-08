import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/hodlocker_template.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('HODLocker Template', () {
    late HODLockerTemplate template;
    late SVScript hodLockerScript;
    late String pubKeyHashHex;
    late int lockHeight;

    setUp(() {
      template = HODLockerTemplate();
      pubKeyHashHex = '1234567890abcdef1234567890abcdef12345678';
      lockHeight = 650000; // Example block height
      
      // Create a HODLocker script
      final builder = HODLockerLockingScriptBuilder(
        HEX.decode(pubKeyHashHex),
        BigInt.from(lockHeight)
      );
      hodLockerScript = builder.getScriptPubkey();
    });

    test('should have correct name', () {
      expect(template.name, equals('HODLocker'));
    });

    test('should match HODLocker script', () {
      expect(template.matches(hodLockerScript), isTrue);
      
      // Should not match other script types
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(template.matches(p2pkScript), isFalse);
    });

    test('should create builder with hex string pubKeyHash', () {
      final params = {
        'pubKeyHash': pubKeyHashHex,
        'lockHeight': lockHeight
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<HODLockerLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(hodLockerScript.toString()));
    });

    test('should create builder with Uint8List pubKeyHash', () {
      final pubKeyHashBytes = Uint8List.fromList(HEX.decode(pubKeyHashHex));
      final params = {
        'pubKeyHash': pubKeyHashBytes,
        'lockHeight': lockHeight
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<HODLockerLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(hodLockerScript.toString()));
    });

    test('should create builder with List<int> pubKeyHash', () {
      final pubKeyHashList = HEX.decode(pubKeyHashHex);
      final params = {
        'pubKeyHash': pubKeyHashList,
        'lockHeight': lockHeight
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<HODLockerLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(hodLockerScript.toString()));
    });

    test('should create builder with different lockHeight formats', () {
      // With BigInt
      final params1 = {
        'pubKeyHash': pubKeyHashHex,
        'lockHeight': BigInt.from(lockHeight)
      };
      final builder1 = template.createBuilder(params1);
      expect(builder1, isA<HODLockerLockingScriptBuilder>());
      
      // With String
      final params2 = {
        'pubKeyHash': pubKeyHashHex,
        'lockHeight': lockHeight.toString()
      };
      final builder2 = template.createBuilder(params2);
      expect(builder2, isA<HODLockerLockingScriptBuilder>());
    });

    test('should throw error when parameters are missing', () {
      // Missing pubKeyHash
      final params1 = {'lockHeight': lockHeight};
      expect(() => template.createBuilder(params1), throwsArgumentError);
      
      // Missing lockHeight
      final params2 = {'pubKeyHash': pubKeyHashHex};
      expect(() => template.createBuilder(params2), throwsArgumentError);
    });

    test('should throw error with invalid pubKeyHash length', () {
      final params = {
        'pubKeyHash': '1234567890', // Too short
        'lockHeight': lockHeight
      };
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should throw error with invalid pubKeyHash type', () {
      final params = {
        'pubKeyHash': 12345, // Invalid type
        'lockHeight': lockHeight
      };
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should throw error with invalid lockHeight type', () {
      final params = {
        'pubKeyHash': pubKeyHashHex,
        'lockHeight': {} // Invalid type
      };
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should throw error when creating unlocking builder', () {
      final params = <String, dynamic>{};
      expect(() => template.createUnlockingBuilder(params), throwsUnsupportedError);
    });

    test('should always return false for canBeSatisfiedBy', () {
      final publicKey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      final availableKeys = [publicKey];
      
      expect(template.canBeSatisfiedBy(availableKeys, hodLockerScript), isFalse);
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(hodLockerScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('HODLocker'));
      expect(info['pubKeyHash'], isA<Uint8List>());
      expect(HEX.encode(info['pubKeyHash']), equals(pubKeyHashHex));
      expect(info['lockHeight'], isA<BigInt>());
      expect(info['lockHeight'], equals(BigInt.from(lockHeight)));
    });

    test('should throw error when extracting info from non-HODLocker script', () {
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkScript), throwsArgumentError);
    });
  });
}
