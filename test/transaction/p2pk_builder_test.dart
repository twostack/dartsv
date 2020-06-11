
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/transaction/p2pk_builder.dart';
import 'package:test/test.dart';

void main() {
  group('#buildPublicKeyOut', () {
    test('should create script from public key', () {
      var pubkey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKLockBuilder(pubkey);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect(script.toString(), equals('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG'));
    });
  });
}
