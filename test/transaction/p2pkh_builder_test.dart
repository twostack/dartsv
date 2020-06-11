import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/transaction/p2pkh_builder.dart';
import 'package:test/test.dart';

void main() {
  group('P2PKH Builder - Locking Script', () {
    test('should create script from livenet address', () {
      var address = Address('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14');
      var lockBulder = P2PKHLockBuilder(address);
      var script = lockBulder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals( 'OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBulder.address.toString(), equals('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14'));
    });

    test('should create script from testnet address', () {
      var address = Address('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33');
      var lockBuilder = P2PKHLockBuilder(address);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals( 'OP_DUP OP_HASH160 20 0xb96b816f378babb1fe585b7be7a2cd16eb99b3e4 OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.toString(), equals('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33'));
    });

    test('should create script from public key', () {
      var pubkey = SVPublicKey.fromHex( '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKHLockBuilder.fromPublicKey(pubkey, networkType: NetworkType.TEST);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals('OP_DUP OP_HASH160 20 0x9674af7395592ec5d91573aa8d6557de55f60147 OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.networkType, equals(NetworkType.TEST));
    });
  });
  
  group ('P2PKH Builder - Unlocking Script deserialize', () {
    test('should identify this known unlocking script (uncompressed pubkey version)', () {
      var pubkey = SVPublicKey.fromHex("04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6");
      var signature = SVSignature.fromTxFormat("3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601");
      var script = SVScript.fromString('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6');

      var unlockBuilder = P2PKHUnlockBuilder(pubkey);
      unlockBuilder.fromScript(script);

      expect(unlockBuilder.signature, isNotNull);
      expect(unlockBuilder.signerPubkey, isNotNull);
      expect(unlockBuilder.signerPubkey.toString(), equals(pubkey.toString()));
      expect(unlockBuilder.signature.toString(), equals(signature.toString()));

    });

  });
}
