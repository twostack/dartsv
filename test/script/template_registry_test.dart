import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/p2pk_template.dart';
import 'package:dartsv/src/script/templates/p2pkh_template.dart';
import 'package:dartsv/src/script/templates/p2sh_template.dart';
import 'package:dartsv/src/script/templates/template_registry.dart';
import 'package:test/test.dart';

void main() {
  group('Template Registry', () {
    late ScriptTemplateRegistry registry;

    setUp(() {
      // Initialize a fresh registry for each test
      registry = ScriptTemplateRegistry();
      TemplateRegistry.initialize();
    });

    test('should initialize with standard templates', () {
      // Check that standard templates are registered
      expect(registry.getTemplate('P2PKH'), isA<P2PKHTemplate>());
      expect(registry.getTemplate('P2PK'), isA<P2PKTemplate>());
      expect(registry.getTemplate('P2SH'), isA<P2SHTemplate>());
    });

    test('should return null for non-existent template', () {
      expect(registry.getTemplate('NON_EXISTENT'), isNull);
    });

    test('should identify script type', () {
      // Create a P2PKH script
      final pubKeyHash = '06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3';
      final p2pkhScript = SVScript.fromString('OP_DUP OP_HASH160 20 0x$pubKeyHash OP_EQUALVERIFY OP_CHECKSIG');
      
      // Identify script type
      final scriptType = registry.identifyScriptType(p2pkhScript);
      expect(scriptType, equals('P2PKH'));
    });

    test('should identify P2PK script type', () {
      // Create a P2PK script
      final pubKey = '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da';
      final p2pkScript = SVScript.fromString('33 0x$pubKey OP_CHECKSIG');
      
      // Identify script type
      final scriptType = registry.identifyScriptType(p2pkScript);
      expect(scriptType, equals('P2PK'));
    });

    test('should identify P2SH script type', () {
      // Create a P2SH script
      final scriptHash = '45ea3f9133e7b1cef30ba606f8433f993e41e159';
      final p2shScript = SVScript.fromString('OP_HASH160 20 0x$scriptHash OP_EQUAL');
      
      // Identify script type
      final scriptType = registry.identifyScriptType(p2shScript);
      expect(scriptType, equals('P2SH'));
    });

    test('should return null for unknown script pattern', () {
      // Create a non-standard script
      final nonStandardScript = SVScript.fromString('OP_DROP OP_DROP OP_DROP');
      
      // Identify script type
      final scriptType = registry.identifyScriptType(nonStandardScript);
      expect(scriptType, isNull);
    });
    
    test('should create locking script builder', () {
      final params = {'publicKey': SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da')};
      final builder = registry.createBuilder('P2PK', params);
      expect(builder, isNotNull);
    });
    
    test('should create unlocking script builder', () {
      final params = {'publicKey': SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da'), 'signature': 'dummy_signature'};
      final builder = registry.createUnlockingBuilder('P2PK', params);
      expect(builder, isNotNull);
    });
    
    test('should extract script info', () {
      final pubKey = '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da';
      final p2pkScript = SVScript.fromString('33 0x$pubKey OP_CHECKSIG');
      
      final info = registry.extractScriptInfo(p2pkScript);
      expect(info, isNotNull);
      expect(info!['type'], equals('P2PK'));
    });
  });
}
