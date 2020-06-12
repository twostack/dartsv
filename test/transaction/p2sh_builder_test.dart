import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/p2sh_builder.dart';
import 'package:test/test.dart';

void main() {
  group('P2SH builder', (){

    test('should create script from another script', () {
      var inner = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      var lockBuilder = P2SHLockBuilder(null);
      lockBuilder.fromScript(inner);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect(script.toString(), equals('OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL'));
    });

  });
}
