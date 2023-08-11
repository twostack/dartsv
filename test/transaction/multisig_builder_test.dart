
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/p2ms_builder.dart';
import 'package:dartsv/src/transaction/transaction_builder.dart';
import 'package:test/test.dart';

void main() {
  var pubKeyHexes = [
    '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da',
    '03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9',
    '021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18',
    '02bf97f572a02a8900246d72c2e8fa3d3798a6e59c4e17de2d131d9c60d0d9b574',
    '036a98a36aa7665874b1ba9130bc6d318e52fd3bdb5969532d7fc09bf2476ff842',
    '033aafcbead78c08b0e0aacc1b0cdb40702a7c709b660bebd286e973242127e15b'
  ];

  var sortkeys = pubKeyHexes.getRange(0, 3).map((key) => SVPublicKey.fromHex(key));

  group('P2MS (multisig) - Locking Script', (){
    test('should create sorted script by default', () {
      //var s = Script.buildMultisigOut(sortkeys, 2);
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 2);
      var script = lockBuilder.getScriptPubkey();
      expect( script.toString(), equals( 'OP_2 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 OP_3 OP_CHECKMULTISIG'));
    });

    test( 'should fail when number of required signatures is greater than number of pubkeys', () {
      expect(sortkeys.length, equals(3));
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 4);
      expect(() => lockBuilder.getScriptPubkey(), throwsException);
    });

    test('should create unsorted script if specified', () {
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 2);
      var unsortedLockBuilder = P2MSLockBuilder(sortkeys.toList(), 2, sorting: false);
      var sortedScript = lockBuilder.getScriptPubkey();
      var unsortedScript = unsortedLockBuilder.getScriptPubkey();

      expect(sortedScript.toString(), isNot(equals(unsortedScript.toString())));
      expect(unsortedScript.toString(), equals( 'OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 OP_3 OP_CHECKMULTISIG'));
    });

    test('can recover state using fromScript', (){
      var script = SVScript.fromString('OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 OP_2 OP_CHECKMULTISIG');

      var lockBuilder = P2MSLockBuilder([], 0);
      lockBuilder.fromScript(script);

      expect(lockBuilder.publicKeys?.length, equals(2));
      expect(lockBuilder.requiredSigs, equals(2));
      expect(lockBuilder.publicKeys[0].toHex(), equals('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da'));
      expect(lockBuilder.publicKeys[1].toHex(), equals('03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9'));
    });
  });


  group('P2MS (multisig) - unlocking Script', () {
    Address fromAddress = Address('mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1');
    Address toAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
    Address changeAddress = Address('mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up');

    var private1 = SVPrivateKey.fromWIF( 'cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
    var private2 = SVPrivateKey.fromWIF( "cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
    var public1 = private1.publicKey;
    var public2 = private2.publicKey;

    var lockBuilder = P2MSLockBuilder([public1, public2], 2);

    var simpleUtxoWith100000Satoshis = {
      "address": fromAddress,
      "txId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
      "outputIndex": 0,
      "scriptPubKey": lockBuilder.getScriptPubkey().toString(),
      "satoshis": BigInt.from(100000)
    };

    test('can perform a multisig spend', () {
      var unlockBuilder = P2MSUnlockBuilder();
      var signer1 = TransactionSigner(SighashType.SIGHASH_ALL, private1);
      var signer2 = TransactionSigner(SighashType.SIGHASH_ALL, private2);
      var transaction = TransactionBuilder()
          .spendFromUtxoMapWithSigner(signer1, simpleUtxoWith100000Satoshis, unlockBuilder)
          .spendTo(P2PKHLockBuilder(toAddress), BigInt.from(500000) )
          .sendChangeToAddress(changeAddress)
          .withFeePerKb(50)
          .build(false);

      transaction.version = 1;

      // transaction.signInput(0, private1);
      // transaction.signInput(0, private2);

      expect(unlockBuilder.signatures.length, equals(2));
      expect(unlockBuilder.getScriptSig().toString(), equals('OP_0 71 0x30440220506a721a4aca80943146700333be6f5f0abd96798b4b5e21d14a45f6f3e1c96d022074be7308c17a86d327ad6f9b59116f45edff218187e5a6bcff6c58150ec94f9700 71 0x304402205133d18807f1261bd0712a6d334cf85a286fe3aaec08efbce824a31efe60c0a9022048d52308728a602a046adceb990188062955a0f20f390895066325406b41644700'));

      //Interpreter().verifyScript(scriptSig, scriptPubkey) FIXME: for another day
    });

    test('can reconstruct P2MS unlocking script', (){

      var script = SVScript.fromString('OP_0 0x47 0x3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01 0x48 0x30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501');
      var unlockBuilder = P2MSUnlockBuilder();
      unlockBuilder.fromScript(script);

      expect(unlockBuilder.signatures.length, equals(2));
      expect(unlockBuilder.signatures[0].toTxFormat(), equals('3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01'));
      expect(unlockBuilder.signatures[1].toTxFormat(), equals('30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501'));

    });
  });

}
