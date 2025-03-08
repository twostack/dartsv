import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/author_identity_template.dart';
import 'package:test/test.dart';

void main() {
  group('AuthorIdentity Template', () {
    late AuthorIdentityTemplate template;
    late SVScript authorIdentityScript;
    late String signingAlgorithm;
    late String publicKey;
    late String signature;

    setUp(() {
      template = AuthorIdentityTemplate();
      signingAlgorithm = 'BITCOIN_ECDSA';
      publicKey = '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da';
      signature = 'H0k7xyMp76VRhUQ1X8kLaQUEFJRbWzgH0eWn1rQRr0HYWzfO2VBpZVEr1wm6TRQvfvUqxKq/TRxzHB6YKa5wL+U=';
      
      // Create an AuthorIdentity script
      final builder = AuthorIdentityLockingScriptBuilder(signingAlgorithm, publicKey, signature);
      authorIdentityScript = builder.getScriptPubkey();
    });

    test('should have correct name', () {
      expect(template.name, equals('AuthorIdentity'));
    });

    test('should match AuthorIdentity script', () {
      expect(template.matches(authorIdentityScript), isTrue);
      
      // Should not match other script types
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(template.matches(p2pkScript), isFalse);
    });

    test('should create builder with required parameters', () {
      final params = {
        'signingAlgorithm': signingAlgorithm,
        'publicKey': publicKey,
        'signature': signature
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<AuthorIdentityLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(authorIdentityScript.toString()));
    });

    test('should throw error when parameters are missing', () {
      // Missing signingAlgorithm
      final params1 = {
        'publicKey': publicKey,
        'signature': signature
      };
      expect(() => template.createBuilder(params1), throwsArgumentError);
      
      // Missing publicKey
      final params2 = {
        'signingAlgorithm': signingAlgorithm,
        'signature': signature
      };
      expect(() => template.createBuilder(params2), throwsArgumentError);
      
      // Missing signature
      final params3 = {
        'signingAlgorithm': signingAlgorithm,
        'publicKey': publicKey
      };
      expect(() => template.createBuilder(params3), throwsArgumentError);
    });

    test('should throw error when creating unlocking builder', () {
      final params = <String, dynamic>{};
      expect(() => template.createUnlockingBuilder(params), throwsUnsupportedError);
    });

    test('should always return false for canBeSatisfiedBy', () {
      final svPublicKey = SVPublicKey.fromHex(publicKey);
      final availableKeys = [svPublicKey];
      
      expect(template.canBeSatisfiedBy(availableKeys, authorIdentityScript), isFalse);
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(authorIdentityScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('AuthorIdentity'));
      expect(info['prefix'], equals('15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva'));
      expect(info['signingAlgorithm'], equals(signingAlgorithm));
      expect(info['publicKey'], equals(publicKey));
      expect(info['signature'], equals(signature));
    });

    test('should throw error when extracting info from non-AuthorIdentity script', () {
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkScript), throwsArgumentError);
    });
  });
}
