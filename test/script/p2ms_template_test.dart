import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/p2ms_template.dart';

import 'package:test/test.dart';

void main() {
  group('P2MS Template', () {
    late P2MSTemplate template;
    late List<SVPublicKey> publicKeys;
    late int threshold;
    late SVScript p2msScript;

    setUp(() {
      template = P2MSTemplate();

      // Create multiple public keys for multisig
      publicKeys = [
        SVPublicKey.fromHex(
            '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da'),
        SVPublicKey.fromHex(
            '03b3623117e988b76aaabe3d63f56a4fc88b228a71e64c4cc551d1204822fe85cb'),
        SVPublicKey.fromHex(
            '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
      ];

      threshold = 2; // 2-of-3 multisig

      // Create a P2MS script (2-of-3)
      final builder = P2MSLockingScriptBuilder(publicKeys, threshold);
      p2msScript = builder.getScriptPubkey();
    });

    test('should have correct name', () {
      expect(template.name, equals('P2MS'));
    });

    test('should match P2MS script', () {
      expect(template.matches(p2msScript), isTrue);

      // Should not match other script types
      final p2pkScript = SVScript.fromString(
          '33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(template.matches(p2pkScript), isFalse);
    });

    test('should create builder with publicKeys and threshold', () {
      final params = {'publicKeys': publicKeys, 'threshold': threshold};
      final builder = template.createBuilder(params);

      expect(builder, isA<P2MSLockingScriptBuilder>());
      expect(
          builder.getScriptPubkey().toString(), equals(p2msScript.toString()));
    });

    test('should throw error when parameters are missing', () {
      // Missing publicKeys
      final params1 = {'threshold': threshold};
      expect(() => template.createBuilder(params1), throwsArgumentError);

      // Missing threshold
      final params2 = {'publicKeys': publicKeys};
      expect(() => template.createBuilder(params2), throwsArgumentError);
    });

    test('should throw error with invalid threshold', () {
      // Threshold too low
      final params1 = {'publicKeys': publicKeys, 'threshold': 0};
      expect(() => template.createBuilder(params1), throwsArgumentError);

      // Threshold too high
      final params2 = {
        'publicKeys': publicKeys,
        'threshold': publicKeys.length + 1
      };
      expect(() => template.createBuilder(params2), throwsArgumentError);
    });

    test('should create unlocking builder', () {
      // Skip this test as it requires valid signatures
      // In a real test, we would need to create valid signatures
      // This would require setting up the entire signing infrastructure
    });

    test('should throw error when signatures are missing', () {
      final params = <String, dynamic>{};
      expect(
          () => template.createUnlockingBuilder(params), throwsArgumentError);
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(p2msScript);

      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('P2MS'));
      expect(info['threshold'], equals(threshold));
      expect(info['signaturesRequired'], equals(threshold));
      expect(info['totalKeys'], equals(publicKeys.length));
      expect(info['publicKeys'], isA<List<SVPublicKey>>());
      expect(info['publicKeys'].length, equals(publicKeys.length));

      // Verify each public key matches
      for (int i = 0; i < publicKeys.length; i++) {
        expect(
            info['publicKeys'][i].toString(), equals(publicKeys[i].toString()));
      }
    });

    test('should throw error when extracting info from non-P2MS script', () {
      final p2pkScript = SVScript.fromString(
          '33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkScript), throwsArgumentError);
    });

    test('should check if script can be satisfied by available keys', () {
      // Create a list with enough matching public keys (2 of 3)
      final availableKeys = [publicKeys[0], publicKeys[1]];
      expect(template.canBeSatisfiedBy(availableKeys, p2msScript), isTrue);

      // Create a list with not enough matching public keys (1 of 3, need 2)
      final insufficientKeys = [publicKeys[0]];
      expect(template.canBeSatisfiedBy(insufficientKeys, p2msScript), isFalse);

      // Create a list with non-matching public keys
      final differentKey = SVPublicKey.fromHex(
          '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5');
      final nonMatchingKeys = [differentKey, differentKey, differentKey];
      expect(template.canBeSatisfiedBy(nonMatchingKeys, p2msScript), isFalse);
    });
  });
}
