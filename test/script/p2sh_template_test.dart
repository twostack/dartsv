import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/p2sh_template.dart';
import 'package:dartsv/src/transaction/p2sh_builder.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('P2SH Template', () {
    late P2SHTemplate template;
    late SVScript redeemScript;
    late SVScript p2shScript;
    late String scriptHash;

    setUp(() {
      template = P2SHTemplate();
      // Create a P2PKH script as our redeem script
      redeemScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      
      // Calculate the hash160 of the redeem script
      final hash = hash160(redeemScript.buffer);
      scriptHash = HEX.encode(hash);
      
      // Create the P2SH script
      p2shScript = SVScript.fromString('OP_HASH160 20 0x$scriptHash OP_EQUAL');
    });

    test('should have correct name', () {
      expect(template.name, equals('P2SH'));
    });

    test('should match P2SH script', () {
      expect(template.matches(p2shScript), isTrue);
      
      // Should not match other script types
      final p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      expect(template.matches(p2pkhScript), isFalse);
    });

    test('should create builder with SVScript', () {
      final params = {'redeemScript': redeemScript};
      final builder = template.createBuilder(params);
      
      expect(builder, isA<P2SHLockBuilder>());
      expect(builder.getScriptPubkey().toString(), equals(p2shScript.toString()));
    });

    test('should create builder with hex string', () {
      final params = {'redeemScript': redeemScript.toHex()};
      final builder = template.createBuilder(params);
      
      expect(builder, isA<P2SHLockBuilder>());
      expect(builder.getScriptPubkey().toString(), equals(p2shScript.toString()));
    });

    test('should throw error when redeemScript is missing', () {
      final params = <String, dynamic>{};
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should create unlocking builder', () {
      final params = {'redeemScript': redeemScript};
      final builder = template.createUnlockingBuilder(params);
      
      expect(builder, isA<P2SHUnlockBuilder>());
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(p2shScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('P2SH'));
      expect(info['scriptHash'], equals(scriptHash));
    });

    test('should throw error when extracting info from non-P2SH script', () {
      final p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkhScript), throwsArgumentError);
    });
  });
}
