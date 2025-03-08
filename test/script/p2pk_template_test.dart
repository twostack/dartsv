import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/p2pk_template.dart';
import 'package:dartsv/src/transaction/p2pk_builder.dart';
import 'package:test/test.dart';

void main() {
  group('P2PK Template', () {
    late P2PKTemplate template;
    late SVPublicKey publicKey;
    late SVScript p2pkScript;

    setUp(() {
      template = P2PKTemplate();
      publicKey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
    });

    test('should have correct name', () {
      expect(template.name, equals('P2PK'));
    });

    test('should match P2PK script', () {
      expect(template.matches(p2pkScript), isTrue);
      
      // Should not match other script types
      final p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      expect(template.matches(p2pkhScript), isFalse);
    });

    test('should create builder with SVPublicKey', () {
      final params = {'publicKey': publicKey};
      final builder = template.createBuilder(params);
      
      expect(builder, isA<P2PKLockBuilder>());
      expect(builder.getScriptPubkey().toString(), equals(p2pkScript.toString()));
    });

    test('should create builder with hex string', () {
      final params = {'publicKey': publicKey.toHex()};
      final builder = template.createBuilder(params);
      
      expect(builder, isA<P2PKLockBuilder>());
      expect(builder.getScriptPubkey().toString(), equals(p2pkScript.toString()));
    });

    test('should throw error when publicKey is missing', () {
      final params = <String, dynamic>{};
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should create unlocking builder', () {
      final params = {'publicKey': publicKey, 'signature': 'dummy_signature'};
      final builder = template.createUnlockingBuilder(params);
      
      expect(builder, isA<P2PKUnlockBuilder>());
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(p2pkScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('P2PK'));
      expect(info['publicKey'], isA<SVPublicKey>());
      expect(info['publicKeyHex'], equals(publicKey.toHex()));
      expect(info['isCompressed'], equals(publicKey.isCompressed));
    });

    test('should throw error when extracting info from non-P2PK script', () {
      final p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkhScript), throwsArgumentError);
    });

    test('should check if script can be satisfied by available keys', () {
      // Create a list with the matching public key
      final availableKeys = [publicKey];
      expect(template.canBeSatisfiedBy(availableKeys, p2pkScript), isTrue);
      
      // Create a list with a different public key
      final differentKey = SVPublicKey.fromHex('03b3623117e988b76aaabe3d63f56a4fc88b228a71e64c4cc551d1204822fe85cb');
      final differentKeys = [differentKey];
      expect(template.canBeSatisfiedBy(differentKeys, p2pkScript), isFalse);
    });
  });
}
