
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/privatekey.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/sighash.dart';
import 'package:dartsv/src/transaction/p2pk_builder.dart';
import 'package:dartsv/src/transaction/transaction.dart';
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

    test('', (){
      var coinbaseOutput = "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000";
      var privateKey = SVPrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
      var changeAddress = Address("mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
      var recipientAddress = Address("n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

      //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
      //this transaction contains the UTXO we are interested in
      var txWithUTXO = Transaction.fromHex(coinbaseOutput);

      //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
      //the Transaction we are spending from.
      var utxo = txWithUTXO.outputs[0]; //looking at the decoded JSON we can see that our UTXO in at vout[0]
      var pubkey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKLockBuilder(pubkey);
      var signer = TransactionSigner(  SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID, privateKey );

      var locker = P2PKLockBuilder(pubkey);
      var unlocker = P2PKUnlockBuilder(pubkey);
      var txn = TransactionBuilder()
          .spendFromOutputWithSigner(signer, txWithUTXO.id, 0, utxo.satoshis, TransactionInput.MAX_SEQ_NUMBER, unlocker) //set global sequenceNumber/nLocktime time for each Input created
          .spendTo(locker, BigInt.from(50000000)) //spend half of a bitcoin (we should have 1 in the UTXO)
          .sendChangeToAddress(changeAddress) // spend change to myself
          .withFeePerKb(50)
          .build(false);

      //FIXME: Assert spends correctly
    });
  });
}
