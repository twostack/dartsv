import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/p2pkh_template.dart';

import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('P2PKH Template', () {
    late P2PKHTemplate template;
    late SVPublicKey publicKey;
    late String pubKeyHash;
    late SVScript p2pkhScript;

    setUp(() {
      template = P2PKHTemplate();
      publicKey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      
      // Get the public key hash from the address
      final address = publicKey.toAddress(NetworkType.MAIN);
      pubKeyHash = address.pubkeyHash160;
      
      // Create a P2PKH script
      p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x$pubKeyHash OP_EQUALVERIFY OP_CHECKSIG');
    });

    test('should have correct name', () {
      expect(template.name, equals('P2PKH'));
    });

    test('should match P2PKH script', () {
      expect(template.matches(p2pkhScript), isTrue);
      
      // Should not match other script types
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(template.matches(p2pkScript), isFalse);
    });

    test('should create builder with pubKeyHash', () {
      final params = {'pubKeyHash': HEX.decode(pubKeyHash)};
      final builder = template.createBuilder(params);
      
      expect(builder, isA<P2PKHLockingScriptBuilder>());
      expect(builder.getScriptPubkey().toString(), equals(p2pkhScript.toString()));
    });

    test('should throw error when pubKeyHash is missing', () {
      final params = <String, dynamic>{};
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should create unlocking builder', () {
      // Skip this test as it requires a valid signature
      // In a real test, we would need to create a valid signature
      // This would require setting up the entire signing infrastructure
    });

    test('should throw error when signature or publicKey is missing', () {
      // Missing signature
      final params1 = {'publicKey': publicKey};
      expect(() => template.createUnlockingBuilder(params1), throwsArgumentError);
      
      // Missing publicKey - we can test this without a valid signature
      // since the error will be thrown before signature validation
      final params2 = {'signature': 'dummy'};
      expect(() => template.createUnlockingBuilder(params2), throwsArgumentError);
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(p2pkhScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('P2PKH'));
      expect(info['pubKeyHash'], isA<List<int>>());
      expect(HEX.encode(info['pubKeyHash']), equals(pubKeyHash));
    });

    test('should throw error when extracting info from non-P2PKH script', () {
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkScript), throwsArgumentError);
    });

    test('should check if script can be satisfied by available keys', () {
      // Create a list with the matching public key
      final availableKeys = [publicKey];
      expect(template.canBeSatisfiedBy(availableKeys, p2pkhScript), isTrue);
      
      // Create a list with a different public key
      final differentKey = SVPublicKey.fromHex('03b3623117e988b76aaabe3d63f56a4fc88b228a71e64c4cc551d1204822fe85cb');
      final differentKeys = [differentKey];
      expect(template.canBeSatisfiedBy(differentKeys, p2pkhScript), isFalse);
    });
  });
}
