import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:dartsv/src/transaction/p2pkh_builder.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:test/test.dart';


main() {
    var tx1hex = '01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006a473044022013fa3089327b50263029265572ae1b022a91d10ac80eb4f32f291c914533670b02200d8a5ed5f62634a7e1a0dc9188a3cc460a986267ae4d58faf50c79105431327501210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0150690f00000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac00000000';
    var tx1id = '779a3e5b3c2c452c85333d8521f804c1a52800e60f4b7c3bbe36f4bab350b72c';
    var txEmptyHex = '01000000000000000000';

    var tx2hex = '0100000001e07d8090f4d4e6fcba6a2819e805805517eb19e669e9d2f856b41d4277953d640000000091004730440220248bc60bb309dd0215fbde830b6371e3fdc55685d11daa9a3c43828892e26ce202205f10cd4011f3a43657260a211f6c4d1fa81b6b6bdd6577263ed097cc22f4e5b50147522102fa38420cec94843ba963684b771ba3ca7ce1728dc2c7e7cade0bf298324d6b942103f948a83c20b2e7228ca9f3b71a96c2f079d9c32164cd07f08fbfdb483427d2ee52aeffffffff01180fe200000000001976a914ccee7ce8e8b91ec0bc23e1cfb6324461429e6b0488ac00000000';
    var unsupportedTxObj = '{"version":1,"inputs":[{"prevTxId":"a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458","outputIndex":0,"sequenceNumber":4294967295,"script":"OP_1","output":{"satoshis":1020000,"script":"OP_1 OP_ADD OP_2 OP_EQUAL"}}],"outputs":[{"satoshis":1010000,"script":"OP_DUP OP_HASH160 20 0x7821c0a3768aa9d1a37e16cf76002aef5373f1a8 OP_EQUALVERIFY OP_CHECKSIG"}],"nLockTime":0}';
    var txCoinJoinHex = '0100000013440a4e2471a0afd66c9db54db7d414507981eb3db35970dadf722453f08bdc8d0c0000006a47304402200098a7f838ff267969971f5d9d4b2c1db11b8e39c81eebf3c8fe22dd7bf0018302203fa16f0aa3559752462c20ddd8a601620eb176b4511507d11a361a7bb595c57c01210343ead2c0e2303d880bf72dfc04fc9c20d921fc53949c471e22b3c68c0690b828ffffffff0295eef5ad85c9b6b91a3d77bce015065dc64dab526b2f27fbe56f51149bb67f100000006b483045022100c46d6226167e6023e5a058b1ae541c5ca4baf4a69afb65adbfce2cc276535a6a022006320fdc8a438009bbfebfe4ab63e415ee231456a0137d167ee2113677f8e3130121032e38a3e15bee5ef272eaf71033a054637f7b74a51882e659b0eacb8db3e417a9ffffffffee0a35737ab56a0fdb84172c985f1597cffeb33c1d8e4adf3b3b4cc6d430d9b50a0000006b483045022100d02737479b676a35a5572bfd027ef9713b2ef34c87aabe2a2939a448d06c0569022018b262f34191dd2dcf5cbf1ecae8126b35aeb4afcb0426922e1d3dfc86e4dc970121022056d76bd198504c05350c415a80900aaf1174ad95ef42105c2c7976c7094425ffffffffee0a35737ab56a0fdb84172c985f1597cffeb33c1d8e4adf3b3b4cc6d430d9b5100000006a47304402207f541994740dd1aff3dbf633b7d7681c5251f2aa1f48735370dd4694ebdb049802205f4c92f3c9d8e3e758b462a5e0487c471cf7e58757815200c869801403c5ed57012102778e7fe0fc66a2746a058bbe25029ee32bfbed75a6853455ffab7c2bf764f1aeffffffff0295eef5ad85c9b6b91a3d77bce015065dc64dab526b2f27fbe56f51149bb67f050000006a473044022050304b69e695bdba599379c52d872410ae5d78804d3f3c60fb887fd0d95f617b02205f0e27fd566849f7be7d1965219cd63484cc0f37b77b62be6fdbf48f5887ae01012103c8ac0d519ba794b2e3fe7b85717d48b8b47f0e6f94015d0cb8b2ca84bce93e22ffffffff490673d994be7c9be1a39c2d45b3c3738fde5e4b54af91740a442e1cde947114110000006b48304502210085f6b6285d30a5ea3ee6b6f0e73c39e5919d5254bc09ff57b11a7909a9f3f6b7022023ffc24406384c3ee574b836f57446980d5e79c1cd795136a2160782544037a9012103152a37a23618dcc6c41dbb0d003c027215c4ce467bffc29821e067d97fa052e7ffffffffc1365292b95156f7d68ad6dfa031910f3284d9d2e9c267670c5cfa7d97bae482010000006b483045022100e59095f9bbb1daeb04c8105f6f0cf123fcf59c80d319a0e2012326d12bb0e02702206d67b31b24ed60b3f3866755ce122abb09200f9bb331d7be214edfd74733bb830121026db18f5b27ce4e60417364ce35571096927339c6e1e9d0a9f489be6a4bc03252ffffffff0295eef5ad85c9b6b91a3d77bce015065dc64dab526b2f27fbe56f51149bb67f0d0000006b483045022100ec5f0ef35f931fa047bb0ada3f23476fded62d8f114fa547093d3b5fbabf6dbe0220127d6d28388ffeaf2a282ec5f6a7b1b7cc2cb8e35778c2f7c3be834f160f1ff8012102b38aca3954870b28403cae22139004e0756ae325208b3e692200e9ddc6e33b54ffffffff73675af13a01c64ee60339613debf81b9e1dd8d9a3515a25f947353459d3af3c0c0000006b483045022100ff17593d4bff4874aa556c5f8f649d4135ea26b37baf355e793f30303d7bfb9102200f51704d8faccbaa22f58488cb2bebe523e00a436ce4d58179d0570e55785daa0121022a0c75b75739d182076c16d3525e83b1bc7362bfa855959c0cd48e5005140166ffffffff73675af13a01c64ee60339613debf81b9e1dd8d9a3515a25f947353459d3af3c0e0000006b483045022100c7d5a379e2870d03a0f3a5bdd4054a653b29804913f8720380a448f4e1f19865022051501eae29ba44a13ddd3780bc97ac5ec86e881462d0e08d9cc4bd2b29bcc815012103abe21a9dc0e9f995e3c58d6c60971e6d54559afe222bca04c2b331f42b38c0f3ffffffff6f70aeaa54516863e16fa2082cb5471e0f66b4c7dac25d9da4969e70532f6da00d0000006b483045022100afbeaf9fe032fd77c4e46442b178bdc37c7d6409985caad2463b7ab28befccfd0220779783a9b898d94827ff210c9183ff66bfb56223b0e0118cbba66c48090a4f700121036385f64e18f00d6e56417aa33ad3243356cc5879342865ee06f3b2c17552fe7efffffffffae31df57ccb4216853c0f3cc5af1f8ad7a99fc8de6bc6d80e7b1c81f4baf1e4140000006a473044022076c7bb674a88d9c6581e9c26eac236f6dd9cb38b5ffa2a3860d8083a1751302e022033297ccaaab0a6425c2afbfb6525b75e6f27cd0c9f23202bea28f8fa8a7996b40121031066fb64bd605b8f9d07c45d0d5c42485325b9289213921736bf7b048dec1df3ffffffff909d6efb9e08780c8b8e0fccff74f3e21c5dd12d86dcf5cbea494e18bbb9995c120000006a47304402205c945293257a266f8d575020fa409c1ba28742ff3c6d66f33059675bd6ba676a02204ca582141345a161726bd4ec5f53a6d50b2afbb1aa811acbad44fd295d01948501210316a04c4b9dc5035bc9fc3ec386896dcba281366e8a8a67b4904e4e4307820f56ffffffff90ac0c55af47a073de7c3f98ac5a59cd10409a8069806c8afb9ebbbf0c232436020000006a47304402200e05f3a9db10a3936ede2f64844ebcbdeeef069f4fd7e34b18d66b185217d5e30220479b734d591ea6412ded39665463f0ae90b0b21028905dd8586f74b4eaa9d6980121030e9ba4601ae3c95ce90e01aaa33b2d0426d39940f278325023d9383350923477ffffffff3e2f391615f885e626f70940bc7daf71bcdc0a7c6bf5a5eaece5b2e08d10317c000000006b4830450221009b675247b064079c32b8e632e9ee8bd62b11b5c89f1e0b37068fe9be16ae9653022044bff9be38966d3eae77eb9adb46c20758bc106f91cd022400999226b3cd6064012103239b99cadf5350746d675d267966e9597b7f5dd5a6f0f829b7bc6e5802152abcffffffffe1ce8f7faf221c2bcab3aa74e6b1c77a73d1a5399a9d401ddb4b45dc1bdc4636090000006b483045022100a891ee2286649763b1ff45b5a3ef66ce037e86e11b559d15270e8a61cfa0365302200c1e7aa62080af45ba18c8345b5f37a94e661f6fb1d62fd2f3917aa2897ae4af012102fa6980f47e0fdc80fb94bed1afebec70eb5734308cd30f850042cd9ddf01aebcffffffffe1ce8f7faf221c2bcab3aa74e6b1c77a73d1a5399a9d401ddb4b45dc1bdc4636010000006a4730440220296dbfacd2d3f3bd4224a40b7685dad8d60292a38be994a0804bdd1d1e84edef022000f30139285e6da863bf6821d46b8799a582d453e696589233769ad9810c9f6a01210314936e7118052ac5c4ba2b44cb5b7b577346a5e6377b97291e1207cf5dae47afffffffff0295eef5ad85c9b6b91a3d77bce015065dc64dab526b2f27fbe56f51149bb67f120000006b483045022100b21b2413eb7de91cab6416efd2504b15a12b34c11e6906f44649827f9c343b4702205691ab43b72862ea0ef60279f03b77d364aa843cb8fcb16d736368e432d44698012103f520fb1a59111b3d294861d3ac498537216d4a71d25391d1b3538ccbd8b023f6ffffffff5a7eaeadd2570dd5b9189eb825d6b1876266940789ebb05deeeac954ab520d060c0000006b483045022100949c7c91ae9addf549d828ed51e0ef42255149e29293a34fb8f81dc194c2f4b902202612d2d6251ef13ed936597f979a26b38916ed844a1c3fded0b3b0ea18b54380012103eda1fa3051306238c35d83e8ff8f97aa724d175dede4c0783926c98f106fb194ffffffff15620f5723000000001976a91406595e074efdd41ef65b0c3dba3d69dd3c6e494b88ac58a3fb03000000001976a914b037b0650a691c56c1f98e274e9752e2157d970288ac18c0f702000000001976a914b68642906bca6bb6c883772f35caaeed9f7a1b7888ac83bd5723000000001976a9148729016d0c88ac01d110e7d75006811f283f119788ace41f3823000000001976a9147acd2478d13395a64a0b8eadb62d501c2b41a90c88ac31d50000000000001976a91400d2a28bc7a4486248fab573d72ef6db46f777ea88aca09c0306000000001976a914d43c27ffb4a76590c245cd55447550ffe99f346a88ac80412005000000001976a914997efabe5dce8a24d4a1f3c0f9236bf2f6a2087588ac99bb0000000000001976a914593f550a3f8afe8e90b7bae14f0f0b2c31c4826688ace2c71500000000001976a914ee85450df9ca44a4e330fd0b7d681ec6fbad6fb488acb0eb4a00000000001976a914e7a48c6f7079d95e1505b45f8307197e6191f13888acea015723000000001976a9149537e8f15a7f8ef2d9ff9c674da57a376cf4369b88ac2002c504000000001976a9141821265cd111aafae46ac62f60eed21d1544128388acb0c94f0e000000001976a914a7aef50f0868fe30389b02af4fae7dda0ec5e2e988ac40b3d509000000001976a9140f9ac28f8890318c50cffe1ec77c05afe5bb036888ac9f9d1f00000000001976a914e70288cab4379092b2d694809d555c79ae59223688ac52e85623000000001976a914a947ce2aca9c6e654e213376d8d35db9e36398d788ac21ae0000000000001976a914ff3bc00eac7ec252cd5fb3318a87ac2a86d229e188ace0737a09000000001976a9146189be3daa18cb1b1fa86859f7ed79cc5c8f2b3388acf051a707000000001976a914453b1289f3f8a0248d8d914d7ad3200c6be0d28888acc0189708000000001976a914a5e2e6e7b740cef68eb374313d53a7fab1a8a3cd88ac00000000';


    //This test was generated as an unconfirmed TX that spends from a Coinbase. It breaks things
    //FIXME: Test for this.//
    var coinbaseOutput = "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000";

    Address fromAddress = Address('mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1');
    Address toAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
    Address changeAddress = Address('mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up');
    SVPrivateKey privateKey = SVPrivateKey.fromWIF('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');

    var simpleUtxoWith100000Satoshis = {
        "address": fromAddress,
        "txId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
        "outputIndex": 0,
        "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
        "satoshis": BigInt.from(100000)
    };

    var simpleUtxoWith1000000Satoshis = {
        "address": fromAddress,
        "txId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
        "outputIndex": 0,
        "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
        "satoshis": BigInt.from(1000000)
    };

    HashMap<String, Object> anyoneCanSpendUTXO = HashMap.from(simpleUtxoWith100000Satoshis);
    anyoneCanSpendUTXO["scriptPubKey"] = "OP_TRUE";

    var simpleUtxoWith1BTC = {
        "address": fromAddress,
        "txId": "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
        "outputIndex": 1,
        "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
        "satoshis": BigInt.from(1e8)
    };

    //FIXME: Create a test which asserts that the TransactionID in the TransactionOutput
    //of a parsed transaction actually matches the transactionId of the UTXO we are spending from

    test('bootstrap test - should be able to add two outputs with short addresses', () {

        // var signature = SVSignature.fromPrivateKey(privateKey); //sig class. not actual sig.
        var locker = P2PKHLockBuilder(toAddress);
        var unlocker = P2PKHUnlockBuilder(privateKey.publicKey);
        Transaction tx = Transaction();

        tx.spendTo(Address('1DpLHif3FBFnckw7Fj653VCr5wYQa3Fiow'), BigInt.from(10000),scriptBuilder: P2PKHLockBuilder(Address('1DpLHif3FBFnckw7Fj653VCr5wYQa3Fiow')));
        tx.spendTo(Address('1ArnPQhtRU3voDbLcTRRzBuJtiCPHnKuN'), BigInt.from(123445),scriptBuilder: P2PKHLockBuilder(Address('1ArnPQhtRU3voDbLcTRRzBuJtiCPHnKuN')));
        tx.spendTo(Address('1111111111111111111114oLvT2'), BigInt.from(123445),scriptBuilder: P2PKHLockBuilder(Address('1111111111111111111114oLvT2')) );

        //FIXME: What is the assertion!?
    });

    test('should serialize and deserialize correctly a given transaction', () {
        Transaction transaction = Transaction.fromHex(tx1hex);
        expect(transaction.uncheckedSerialize(), equals(tx1hex));
    });

    test('should parse the version as a signed integer', () {
        var transaction = Transaction.fromHex('ffffffff0000ffffffff');
        expect(transaction.version, equals(-1));
        expect(transaction.nLockTime, equals(0xffffffff));
    });

    var testScript = 'OP_DUP OP_HASH160 20 0x88d9931ea73d60eaf7e5671efc0552b912911f2a OP_EQUALVERIFY OP_CHECKSIG';
    var testScriptHex = '76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac';
    var testPrevTx = 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458';
    var testAmount = BigInt.from(1020000);
    // var signature = SVSignature.fromPrivateKey(privateKey); //sig class. not actual sig.
    var locker = P2PKHLockBuilder(toAddress);
    var unlocker = P2PKHUnlockBuilder(privateKey.publicKey);
    //P2PKHTransaction tx = P2PKHTransaction(P2PKHBuilder(locker, unlocker));
    var testTransaction = new Transaction()
            .spendFromMap({
            'txId': testPrevTx,
            'outputIndex': 0,
            'scriptPubKey': testScript,
            'satoshis': testAmount,
        }, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .spendTo(Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc'),
            testAmount - BigInt.from(10000),
            scriptBuilder : P2PKHLockBuilder(Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc')));

    test('can perform serialization', () {
        expect(testTransaction.inputs[0].satoshis, equals(testAmount));
       // expect(testTransaction.inputs[0].script.toHex(), equals(testScriptHex));  //FIXME: SVScript does not properly process these human-readable script translations right now
        expect(testTransaction.inputs[0].prevTxnId, equals(testPrevTx));
        expect(testTransaction.inputs[0].prevTxnOutputIndex, equals(0));
        expect(testTransaction.outputs[0].satoshis, equals(testAmount - BigInt.from(10000)));
    });

    test("Amount you're spending must be a positive integer value", () {

        // var signature = SVSignature.fromPrivateKey(privateKey); //sig class. not actual sig.
        var locker = P2PKHLockBuilder(toAddress);
        var unlocker = P2PKHUnlockBuilder(privateKey.publicKey);
        Transaction txn = Transaction();
        var destAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
        expect(() => txn.spendTo(destAddress, BigInt.zero,scriptBuilder: P2PKHLockBuilder(destAddress)), throwsException);
    });

    test('returns the fee as value of unspent output', () {
        expect(testTransaction.getFee(), equals(BigInt.from(10000)));
    });

    test('will return zero as the fee for a coinbase', () {
        // block #2: 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098
        var coinbaseTransaction = Transaction.fromHex(
            '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000');
        expect(coinbaseTransaction.isCoinbase(), isTrue);
        expect(coinbaseTransaction.getFee(), equals(BigInt.zero));
    });

    //TODO : I need larger transaction counts that allows me to properly test all code paths for transaction parsing
    test('can correctly count the number of transactions in a 16bit varint', () {

    });

    test('can correctly count the number of transactions in a 32bit varint', () {

    });

    test('can correctly count the number of transactions in a 64bit varint', () {

    });

    test('can serialize to a P2PKH transaction by default', (){
      var privateKey = SVPrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
      var changeAddress = Address("mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
      var recipientAddress = Address("n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

      //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
      //this transaction contains the UTXO we are interested in
      var txWithUTXO = Transaction.fromHex(coinbaseOutput);

      //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
      //the Transaction we are spending from.
      var utxo = txWithUTXO.outputs[0]; //looking at the decoded JSON we can see that our UTXO in at vout[0]

      var locker = P2PKHLockBuilder(recipientAddress);
      var unlocker = P2PKHUnlockBuilder(privateKey.publicKey);
      var txn = Transaction();
          txn.spendFromOutput(utxo, Transaction.NLOCKTIME_MAX_VALUE, scriptBuilder: unlocker) //set global sequenceNumber/nLocktime time for each Input created
          .spendTo(recipientAddress, BigInt.from(50000000),scriptBuilder: locker) //spend half of a bitcoin (we should have 1 in the UTXO)
          .sendChangeTo(changeAddress,scriptBuilder: locker) // spend change to myself
          .withFeePerKb(100000);

      //Sign the Transaction Input
      txn.signInput(0, privateKey, sighashType: SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID);

      //FIXME: Where's the assertion ?

    });
    test('can calculate output amounts and correct change address', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith1000000Satoshis)
            .spendTo(toAddress, BigInt.from(500000),scriptBuilder: P2PKHLockBuilder(toAddress))
            .sendChangeTo(changeAddress,scriptBuilder: P2PKHLockBuilder(changeAddress));
//        transaction.signWith(privateKey);
        transaction.withFeePerKb(100000);

        transaction.signInput( 0, privateKey);

        expect(transaction.outputs.length, equals(2));
        expect(transaction.outputs[1].satoshis, equals(BigInt.from(472899)));
        expect(transaction.outputs[1].script.toString(), equals(P2PKHLockBuilder(changeAddress).getScriptPubkey().toString()));
        var changeLocker = P2PKHLockBuilder(changeAddress);

        //FIXME: I'm not entirely certain this test is valuable. We are baiscally
        //passing in a changeLocker, and checking if it was correctly passed
        var actual = transaction
            .getChangeOutput(changeLocker)
            .script
            .toString();
        var expected = changeLocker.getScriptPubkey().toString();
        expect(actual, equals(expected));
    });


    test('standard hash of transaction should be decoded correctly', () {
        var transaction = Transaction.fromHex(tx1hex);
        expect(transaction.id, equals(tx1id));
    });

    test('serializes an empty transaction', () {
        var transaction = new Transaction();
        transaction.version = 1;
        expect(transaction.uncheckedSerialize(), equals(txEmptyHex));
    });

    test('serializes and deserializes correctly', () {
        var transaction = Transaction.fromHex(tx1hex);
        expect(transaction.uncheckedSerialize(), equals(tx1hex));
    });


    test('transaction creation/serialization test vectors', () async {
        await File("${Directory.current.path}/test/data/tx_creation.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {

            List.from(jsonData).forEach((item) {
                var privKey = SVPrivateKey.fromWIF(item['sign'][0]);
                var utxoMap = item['from'][0][0];
                utxoMap['satoshis'] = BigInt.from(utxoMap['satoshis'] as int);
                var transaction = Transaction().spendFromMap(utxoMap, scriptBuilder: P2PKHUnlockBuilder(privKey.publicKey));

                for (var elem in item['to']) {
                    var addr = Address(elem[0]);
                    transaction.spendTo(Address(elem[0]), BigInt.from(elem[1]), scriptBuilder: P2PKHLockBuilder(addr));
                };

                transaction.version = 1;
                transaction.withFeePerKb(100000);
                transaction.signInput(0, privKey, sighashType: item['sign'][1]);

                expect(transaction.serialize(performChecks: true), equals(item['serialize']));
            });
        });
    });


    //The BIP references "data leaking" from the BitGo incident which can be solved by
    //generating new change addresses and not re-using them. WTF.
    group("BIP69 Sorting", () {
        test('sorts inputs correctly', () {
            var from1 = {
                "txId": '0000000000000000000000000000000000000000000000000000000000000000',
                "outputIndex": 0,
                "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
                "satoshis": BigInt.from(100000)
            };
            var from2 = {
                "txId": '0000000000000000000000000000000000000000000000000000000000000001',
                "outputIndex": 0,
                "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
                "satoshis": BigInt.from(100000)
            };
            var from3 = {
                "txId": '0000000000000000000000000000000000000000000000000000000000000001',
                "outputIndex": 1,
                "scriptPubKey": P2PKHLockBuilder(fromAddress).getScriptPubkey().toString(),
                "satoshis": BigInt.from(100000)
            };
            var tx = new Transaction()
                .spendFromMap(from3)
                .spendFromMap(from2)
                .spendFromMap(from1);
            tx.sort();
            expect(tx.inputs[0].prevTxnId.toString(), equals(from1["txId"]));
            expect(tx.inputs[1].prevTxnId.toString(), equals(from2["txId"]));
            expect(tx.inputs[2].prevTxnId.toString(), equals(from3["txId"]));
            expect(tx.inputs[0].prevTxnOutputIndex, equals(from1["outputIndex"]));
            expect(tx.inputs[1].prevTxnOutputIndex, equals(from2["outputIndex"]));
            expect(tx.inputs[2].prevTxnOutputIndex, equals(from3["outputIndex"]));
        });


        test('sorts outputs correctly', () {
            var tx = Transaction();
            var output1 = TransactionOutput();
            output1.satoshis = BigInt.from(2);
            output1.script = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_0]));
            tx.outputs.add(output1);

            var output2 = TransactionOutput();
            output2.satoshis = BigInt.from(2);
            output2.script = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_1]));
            tx.outputs.add(output2);

            var output3 = TransactionOutput();
            output3.satoshis = BigInt.from(1);
            output3.script = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_0]));
            tx.outputs.add(output3);

            tx.sort();
            expect(tx.outputs[0].satoshis, equals(BigInt.from(1)));
            expect(tx.outputs[1].satoshis, equals(BigInt.from(2)));
            expect(tx.outputs[2].satoshis, equals(BigInt.from(2)));
            expect(tx.outputs[0].script.buffer, equals([OpCodes.OP_0]));
            expect(tx.outputs[1].script.buffer, equals([OpCodes.OP_0]));
            expect(tx.outputs[2].script.buffer, equals([OpCodes.OP_1]));
        });
    });


    test('can recalculate the change amount', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(50000), scriptBuilder: P2PKHLockBuilder(toAddress))
            .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress))
            .withFee(BigInt.zero);
//            .signWith(privateKey);
        transaction.signInput( 0, privateKey);

        var changeLocker = P2PKHLockBuilder(changeAddress);
        expect(transaction
            .getChangeOutput(changeLocker)
            .satoshis, equals(BigInt.from(50000)));

        transaction = transaction
            .spendTo(toAddress, BigInt.from(20000));
//            .signWith(privateKey);
        transaction.signInput( 0, privateKey);

        expect(transaction.outputs.length, equals(3));
        expect(transaction.outputs[2].satoshis, equals(BigInt.from(30000)));
        expect(transaction.outputs[2].script.toString(), equals(changeLocker.getScriptPubkey().toString()));
    });


    test('adds no fee if no change is available', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(99000), scriptBuilder: P2PKHLockBuilder(toAddress));
//            .signWith(privateKey);
        expect(transaction.outputs.length, equals(1));
        expect(transaction.getFee(), equals(BigInt.from(1000))); //fee is implicitly calculated
    });

    test('adds no fee if no money is available', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(100000), scriptBuilder: P2PKHLockBuilder(toAddress))
            .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

        //expect( transaction.getFee(), equals(BigInt.zero)); //FIXME: Why does this fail ?
        expect(transaction.outputs.length, equals(1));
    });

    test('fee can be set up manually', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(80000), scriptBuilder: P2PKHLockBuilder(toAddress))
            .withFee(BigInt.from(10000))
            .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));
        expect(transaction.outputs.length, equals(2));
        expect(transaction.outputs[1].satoshis, equals(BigInt.from(10000)));
    });


    test('fee per kb can be set up manually', () {
        var  inputs = List<TransactionInput>.generate(10, (input) {
            BigInt amountToSpend = simpleUtxoWith100000Satoshis['satoshis'] as BigInt;
            String transactionId = simpleUtxoWith100000Satoshis['txId'] as String;
            int outputIndex = simpleUtxoWith100000Satoshis['outputIndex'] as int;
            String scriptPubKey = simpleUtxoWith100000Satoshis['scriptPubKey'] as String;
            return TransactionInput(transactionId, outputIndex, SVScript.fromString(scriptPubKey), amountToSpend, TransactionInput.UINT_MAX);
        });

        var outputs = List<TransactionOutput>.generate(10, (output) {
            var txo = TransactionOutput();
            txo.transactionId = simpleUtxoWith100000Satoshis['txId'] as String;
            txo.outputIndex = simpleUtxoWith100000Satoshis['outputIndex'] as int;
            txo.script = SVScript.fromString(simpleUtxoWith100000Satoshis['scriptPubKey'] as String);
            txo.satoshis =  simpleUtxoWith100000Satoshis['satoshis'] as BigInt;
            return txo;
        });

        var transaction = new Transaction()
            .spendTo(toAddress, BigInt.from(950000))
            .withFeePerKb(8000)
            .sendChangeTo(changeAddress);
        outputs.forEach((output) {
            transaction.spendFromOutput(output, Transaction.NLOCKTIME_MAX_VALUE, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
        });
//            .signWith(privateKey);

//      expect(transaction._estimateSize(), .should.be.within(1000, 1999)
        expect(transaction.outputs.length, equals(2));
        expect(transaction.outputs[1].satoshis, equals(BigInt.from(37104)));
    });


    test('on second call to sign, change is not recalculated', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(100000), scriptBuilder: P2PKHLockBuilder(toAddress))
            .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));
        expect(transaction.outputs.length, equals(1));
    });

    test('getFee() returns the difference between inputs and outputs if no change address set', () {
        var transaction = new Transaction()
            .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
            .spendTo(toAddress, BigInt.from(1000), scriptBuilder: P2PKHLockBuilder(toAddress));
        expect(transaction.getFee(), equals(BigInt.from(99000)));
    });

    group('adding inputs', () {
        test('utxos are added exactly once', () {
            var tx = new Transaction();
            tx.spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
            tx.spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
            expect(tx.inputs.length, equals(1));
        });
    });


    group('checked serialize', () {
        test('fails if no change address was set', () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.one, scriptBuilder: P2PKHLockBuilder(toAddress));
            expect(() => transaction.serialize(), throwsException);
        });

        test('fails if a high fee was set', () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress))
                .withFee(BigInt.from(50000000))
                .spendTo(toAddress, BigInt.from(40000000), scriptBuilder: P2PKHLockBuilder(toAddress));
            expect(() => transaction.serialize(), throwsA(TypeMatcher<TransactionFeeException>()));
        });


        test('fails if a dust output is created', () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.from(545), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

            expect(() => transaction.serialize(), throwsA(TypeMatcher<TransactionAmountException>()));
        });

        test('does not fail if a dust output is not dust', () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.from(546), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));
            transaction.signInput( 0, privateKey);

            expect(() => transaction.serialize(), returnsNormally);
        });

        test("doesn't fail if a dust output is an op_return", () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .addData(utf8.encode('not dust!'))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

            transaction.signInput(0, privateKey);

            expect(() => transaction.serialize(), returnsNormally);
        });

        test("fails when outputs and fee don't add to total input", () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.from(99900000), scriptBuilder: P2PKHLockBuilder(toAddress))
                .withFee(BigInt.from(99999));

            expect(() => transaction.serialize(), throwsA(TypeMatcher<TransactionFeeException>()));
        });


        test("checks output amount before fee errors", () {
            var transaction = new Transaction();
            transaction.spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
            transaction
                .spendTo(toAddress, BigInt.from(10000000000000), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress))
                .withFee(BigInt.from(5));

            expect(() => transaction.serialize(), throwsA(TypeMatcher<TransactionAmountException>()));
        });


        test('will throw fee error with disableMoreOutputThanInput enabled (but not triggered)', () {
            var transaction = new Transaction();
            transaction.spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
            transaction
                .spendTo(toAddress, BigInt.from(84000000), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(toAddress))
                .withFee(BigInt.from(16000000));

            transaction.transactionOptions.add(TransactionOption.DISABLE_MORE_OUTPUT_THAN_INPUT);
            expect(() => transaction.serialize(), throwsA(TypeMatcher<TransactionFeeException>()));
        });
    });


    group('skipping checks', () {
        test('can skip the check for too much fee', () {
            var txn = Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .withFee(BigInt.from(50000000))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

            txn.signInput( 0, privateKey);
            expect(() => txn.serialize(), throwsException);

            txn.transactionOptions.add(TransactionOption.DISABLE_LARGE_FEES);
            expect(() => txn.serialize(), returnsNormally);
        });

        test('can skip the check that prevents dust outputs', () {
            var txn = Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.from(100), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

            txn.signInput(0, privateKey);

            expect(() => txn.serialize(), throwsException);

            txn.transactionOptions.add(TransactionOption.DISABLE_DUST_OUTPUTS);
            expect(() => txn.serialize(), returnsNormally);
        });



        test('can skip the check that avoids spending more bitcoins than the inputs for a transaction', () {
            var txn = Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(toAddress, BigInt.from(10000000000000), scriptBuilder: P2PKHLockBuilder(toAddress))
                .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(toAddress));

            txn.signInput(0, privateKey);

            expect(() => txn.serialize(), throwsException);

            txn.transactionOptions.add(TransactionOption.DISABLE_MORE_OUTPUT_THAN_INPUT);
            expect(() => txn.serialize(), returnsNormally);
        });
    });


    group('Serialisation', () {
        test('can avoid checked serialize', () {
            var transaction = new Transaction()
                .spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
                .spendTo(fromAddress, BigInt.from(1), scriptBuilder: P2PKHLockBuilder(fromAddress));

            expect(() => transaction.serialize(performChecks: true), throwsException);
            expect(() => transaction.serialize(performChecks: false), returnsNormally);
        });
    });


    group('verify() method', () {
        test('verify() returns appropriate message for negative satoshis', () {
            var tx = new Transaction()
                .spendFromMap({
                'txId': testPrevTx,
                'outputIndex': 0,
                'scriptPubKey': testScript,
                'satoshis': testAmount
            })
                .spendTo(Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc'), testAmount - BigInt.from(10000));

            tx.outputs[0].satoshis = BigInt.from(-100);
            var verificationMsg = tx.verify();
            expect(verificationMsg, equals('transaction txout 0 satoshis is invalid'));
        });
    });


    group('handling the nLockTime', () {
      var MILLIS_IN_SECOND = 1000;
      var timestamp = 1423504946;
      var blockHeight = 342734;
      var date = DateTime.fromMicrosecondsSinceEpoch(timestamp * MILLIS_IN_SECOND);

      //FIXME: I'm not convinced by this test. nLockTime should default to MAX_TIME (0xFFFFFFFF) to signal "ignore"
//      test('handles a null locktime', () {
//        Transaction transaction = new Transaction();
//        expect(transaction.getLockTime(), equals(null));
//      });

      test('handles a simple example', () {
        var future = new DateTime(2025, 10, 30); // Sun Nov 30 2025
        var transaction = new Transaction()..lockUntilDate(future);
        expect(transaction.nLockTime, equals(future.millisecondsSinceEpoch));
        expect(transaction.getLockTime(), equals(future));
      });


      test('sets timelock using a DateTime instance', () {
        var transaction = new Transaction()..lockUntilDate(date);
        expect(transaction.nLockTime, equals(timestamp));
        expect(transaction.getLockTime(), equals(date));
      });

      test('sets timelock using unix timestamp', () {
        var transaction = new Transaction()..lockUntilUnixTime(timestamp * MILLIS_IN_SECOND);
        expect(transaction.nLockTime, equals(timestamp * MILLIS_IN_SECOND));
        expect(transaction.getLockTime(), equals(DateTime.fromMillisecondsSinceEpoch(timestamp * MILLIS_IN_SECOND)));
      });


      test('sets timelock using a blockheight', () {
          var transaction = new Transaction()..lockUntilBlockHeight(blockHeight);
          expect(transaction.nLockTime, equals(blockHeight));
          expect(transaction.getLockTime(), equals(blockHeight));
      });

      test('blockheight on timelock needs to be < 500000000', () {
          var blockHeight = 500000001;
          var tx = new Transaction();

          expect(() => tx.lockUntilBlockHeight(blockHeight), throwsA(TypeMatcher<LockTimeException>()));
      });


      test('fails if the date is too early', () {
          var earlyDate1 = DateTime.fromMillisecondsSinceEpoch(1);
          var earlyDate2 = DateTime.fromMillisecondsSinceEpoch(499999999);

          expect(() => new Transaction().lockUntilDate(earlyDate1), throwsA(TypeMatcher<LockTimeException>()));
          expect(() => new Transaction().lockUntilDate(earlyDate2), throwsA(TypeMatcher<LockTimeException>()));

      });

    test('fails if the block height is negative', () {
      expect(() => new Transaction().lockUntilBlockHeight(-1), throwsA(TypeMatcher<LockTimeException>()));
    });

    test('has a non-max sequenceNumber for effective date locktime tx', () {
      var transaction = new Transaction()
        ..spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .lockUntilDate(date);
      expect(transaction.inputs[0].sequenceNumber, equals(Transaction.DEFAULT_LOCKTIME_SEQNUMBER));
    });

    test('has a non-max sequenceNumber for effective blockheight locktime tx', () {
      var tx = new Transaction()
        ..spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .lockUntilBlockHeight(blockHeight);
      expect(tx.inputs[0].sequenceNumber, equals(Transaction.DEFAULT_LOCKTIME_SEQNUMBER));
    });

    test('should serialize correctly for date locktime ', () {
      var tx = new Transaction()
        ..spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .lockUntilDate(date);
      var serializedTx = tx.uncheckedSerialize();
      var copy = Transaction.fromHex(serializedTx);
      expect(serializedTx, equals(copy.uncheckedSerialize()));
      expect(copy.inputs[0].sequenceNumber, equals(Transaction.DEFAULT_LOCKTIME_SEQNUMBER));
    });

    test('should serialize correctly for a block height locktime', () {
      var tx = new Transaction()
        ..spendFromMap(simpleUtxoWith1BTC, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .lockUntilBlockHeight(blockHeight);
      var serializedTx = tx.uncheckedSerialize();
      var copy = Transaction.fromHex(serializedTx);
      expect(copy.inputs[0].sequenceNumber, equals(Transaction.DEFAULT_LOCKTIME_SEQNUMBER));
      expect(serializedTx, equals(copy.uncheckedSerialize()));
    });
  });

    group ('BIP69 Sorting Fixtures', (){

        // returns index-based order of sorted against original
        List<int> getIndexOrder(List original, List sorted) {
            return sorted.map((value) => original.indexOf(value)).toList();
        };

        test('input sorting ', () async {
            await File("${Directory.current.path}/test/data/bip69.json")
               .readAsString()
               .then((contents) => jsonDecode(contents))
               .then((jsonData) {

                  HashMap.from(jsonData)["inputs"].forEach((vector) {

                      var inputSet = vector["inputs"];
                      var tx = new Transaction();
                      var txInputs = inputSet.map((input) {
                          return TransactionInput(input["txId"], input["vout"], SVScript(), BigInt.zero, TransactionInput.UINT_MAX);
                      }).toList();

                      List<TransactionInput> inputs = List<TransactionInput>.from(txInputs);
                      tx.inputs.addAll(inputs);
                      tx.sort();
                      expect(getIndexOrder(inputs, tx.inputs), equals(vector["expected"]));

                  });
              });
        });


        test('output sorting ', () async {
            await File("${Directory.current.path}/test/data/bip69.json")
                .readAsString()
                .then((contents) => jsonDecode(contents))
                .then((jsonData) {

                HashMap.from(jsonData)["outputs"].forEach((vector) {

                    var outputSet = vector["outputs"];
                    var tx = new Transaction();

                    var txOutputs = outputSet.map((output) {
                        var txOut = TransactionOutput();
                        txOut.script = SVScript.fromByteArray(utf8.encode(output["script"]) as Uint8List);
                        txOut.satoshis = BigInt.from(output["value"]);
                        return txOut;
                    }).toList();

                    List<TransactionOutput> outputs = List<TransactionOutput>.from(txOutputs);
                    tx.outputs.addAll(outputs);
                    tx.sort();
                    expect(getIndexOrder(outputs, tx.outputs), equals(vector["expected"]));

                });
            });
        });
    });


    //FIXME: I feel like there is something more that needs to go on here
  test('handles anyone-can-spend utxo', () {
    var transaction = new Transaction()
      ..spendFromMap(anyoneCanSpendUTXO)
      .spendTo(toAddress, BigInt.from(50000));
    expect(transaction, isNotNull);
  });


  group('inputAmount + outputAmount', () {
    test('returns correct values for simple transaction', () {
      var transaction = new Transaction()
        ..spendFromMap(simpleUtxoWith1BTC)
        .spendTo(toAddress, BigInt.from(40000000))
        .withFeePerKb(100000);
      expect(transaction.inputAmount, equals(BigInt.from(100000000)));
      expect(transaction.outputAmount, equals(BigInt.from(40000000)));
    });

    test('returns correct values for transaction with change', () {
      var transaction = new Transaction()
        .spendFromMap(simpleUtxoWith1BTC)
        .sendChangeTo(changeAddress)
        .spendTo(toAddress, BigInt.from(1000))
        .withFeePerKb(100000);
      expect(transaction.inputAmount, equals(BigInt.from(100000000)));
      expect(transaction.outputAmount, equals(BigInt.from(99972899)));
    });


  });


  group('checks on adding inputs', () {
      //FIXME:
        Transaction transaction = new Transaction();
        BigInt amountToSpend = simpleUtxoWith100000Satoshis['satoshis'] as BigInt;
        String transactionId = simpleUtxoWith100000Satoshis['txId'] as String;
        int outputIndex = simpleUtxoWith100000Satoshis['outputIndex'] as int;
        String scriptPubKey = simpleUtxoWith100000Satoshis['scriptPubKey'] as String;

    });


   group('Signature Validation', (){
     test('works for normal p2pkh', () {
       var transaction = new Transaction()
         .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
         .spendTo(toAddress, BigInt.from(50000), scriptBuilder: P2PKHLockBuilder(toAddress))
         .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(toAddress));

       transaction.signInput(0, privateKey);
       expect(transaction.inputs[0].isFullySigned(), isTrue);
     });


   });


  test('cannot sign input index beyond number of inputs', (){
      var addr = privateKey.toAddress();
      var from1 = {
          "txId": '0000000000000000000000000000000000000000000000000000000000000000',
          "outputIndex": 0,
          "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
          "satoshis": BigInt.from(100000)
      };
      var from2 = {
          "txId": '0000000000000000000000000000000000000000000000000000000000000001',
          "outputIndex": 1,
          "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
          "satoshis": BigInt.from(100000)
      };
      var from3 = {
          "txId": '0000000000000000000000000000000000000000000000000000000000000001',
          "outputIndex": 2,
          "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
          "satoshis": BigInt.from(100000)
      };
      var tx = new Transaction()
          .spendFromMap(from3, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
          .spendFromMap(from2, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
          .spendFromMap(from1, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));

      tx.version = 1;
      tx.signInput(0, privateKey);
      tx.signInput(1, privateKey);
      tx.signInput(2, privateKey);

      expect(tx.inputs[0].script.toHex(), equals('47304402206c7ae0a256e5dc87f8b1d29f44111ba1b3ab4a6ab189912bb5b259a803b90ccc022030295ae8d683c81cea732f222616353f30dc3bbccbf24221a470d0a45abc552700210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e'));
      expect(tx.inputs[1].script.toHex(), equals('483045022100bfc8ed8db89583aad697dc648e8f601bf3ec0a3e94e0bb4407f01d82dad413a302202ca7de4e2b7714287c9c01733009ef08213e822d7bb6bcf253cc44f1324b4d5c00210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e'));
      expect(tx.inputs[2].script.toHex(), equals('473044022066c7337601ec3ef61cddc915c0ca56f543c2d708ca464e00a2b894f82160879f022045151d45f57f9c15bea1dcfe8edb0a0703fcac410c206a59bfb755250828d67300210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e'));
  });

  test('sign rawtransaction', (){
      var rawtx;
      var signedTx;
      var addr = privateKey.toAddress();
      {
          var from1 = {
              "txId": '0000000000000000000000000000000000000000000000000000000000000000',
              "outputIndex": 0,
              "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
              "satoshis": BigInt.from(100000)
          };
          var from2 = {
              "txId": '0000000000000000000000000000000000000000000000000000000000000001',
              "outputIndex": 1,
              "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
              "satoshis": BigInt.from(100000)
          };
          var from3 = {
              "txId": '0000000000000000000000000000000000000000000000000000000000000001',
              "outputIndex": 2,
              "scriptPubKey": P2PKHLockBuilder(addr).getScriptPubkey().toString(),
              "satoshis": BigInt.from(100000)
          };
          var tx = new Transaction()
              .spendFromMap(from3, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
              .spendFromMap(from2, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
              .spendFromMap(from1, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey));
          rawtx = tx.uncheckedSerialize();

          tx.signInput(0, privateKey);
          tx.signInput(1, privateKey);
          tx.signInput(2, privateKey);
          signedTx = tx.uncheckedSerialize();
      }
     
      var tmpTx = Transaction.fromHex(rawtx);

      // for sign input, you must add [satoshis] [scriptPubkey]
      // and update [UnlockingScriptBuilder]
      tmpTx.inputs[0].satoshis = BigInt.from(100000);
      tmpTx.inputs[0].subScript = P2PKHLockBuilder(addr).getScriptPubkey();
      tmpTx.inputs[0].scriptBuilder = P2PKHUnlockBuilder(privateKey.publicKey);
      tmpTx.inputs[1].satoshis = BigInt.from(100000);
      tmpTx.inputs[1].subScript = P2PKHLockBuilder(addr).getScriptPubkey();
      tmpTx.inputs[1].scriptBuilder = P2PKHUnlockBuilder(privateKey.publicKey);
      tmpTx.inputs[2].satoshis = BigInt.from(100000);
      tmpTx.inputs[2].subScript = P2PKHLockBuilder(addr).getScriptPubkey();
      tmpTx.inputs[2].scriptBuilder = P2PKHUnlockBuilder(privateKey.publicKey);

      tmpTx.signInput(0, privateKey);
      tmpTx.signInput(1, privateKey);
      tmpTx.signInput(2, privateKey);
      expect(tmpTx.uncheckedSerialize(), equals(signedTx));
  });

  test('can craft a large output txn', () async {
    // var fundingTxHex = "02000000032829d7d8e6381d23b162ff3be22b4349fc334034429b1f80a0d2a26d5122004b0000000048473044022065e24ce830907a8d6be3ed37c2a927979bbfbaf61d3652ca86be23fa8c8ad777022035d6bf8b4450c178f1f103167c2e9739dd81bb71dc96d477ad390a7c8c06943041feffffff8650e77205b61bcf525ea783e2c9472ddb3a32ef8dfc5ce0f7ab68a5eb33664b000000006a473044022035b94963aa8f180f106933f30de73715f3b31660dbe546567e7b7e1ca6af1c3b0220088c3ab7d45f06386168074d008b23230ce598862a864e4e7be9cf25263fbcc5412103afc7c94f8dd7cf7f7ab1e6b2334f26d930f27f01fad77dba260713e18a9d7f1ffeffffff8650e77205b61bcf525ea783e2c9472ddb3a32ef8dfc5ce0f7ab68a5eb33664b010000006b483045022100bd9164c568adde08bd929e47dd8b058efa418c79064bc0cbb4cfeb1dc03c5ee002205d8130febcc1d2085f153ebc27b0c4e680d09ec58945306fffc37aa404c3a8c041210330aff1a7e5417393f90eb1bf221c86686e0e3ba25d2696aaa20da549b7d4b3f9feffffff0200ca9a3b000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac779d1200000000001976a914242c4189f7d095e23bc24b05278497d0e6202a2a88ac92070000";
    var fundingTxHex = "020000000428cc8cbb8f691deda86396bdb3d36319556b98a241ba98d498c6a2f53ed095ff0000000049483045022100da68bfb00fa6d5f6fd0f188583122a1f54972654c6806a37548b379056e7873302206e020bcc81a69bd40261ec5a9086b52967f87da3be8f80cd7a68ae1cfef3dd5041feffffffd9f087483a5f6923ff35d0786295feb6bc7a934c76bc49788c6fd73f1806445100000000484730440220042a5a8fd4a493a6df85561f97e709f81e5bbf2fd597f516399a6f679215fdf5022031bcf04ba538c92da6cccd74c1079d242d26cf8b7e1652713820cbd96cb01bb041feffffff1224f9e5295385b838dd3c91f3a5bfb3dabf107142c144b6ebfe1002aed521ae000000004847304402204d6941c4b42f40799b8fb3005e228d41d902ebca0ca75b633ace06f6588c80a302203a7b527d1651c3a2d10890ab66adebfbf25e0207d2c23f574270a9d86928463241feffffff4ce2cc0e28bb7358d2845e43427f24a9c675cd760725e8e1e7931b1ffa90007a00000000484730440220183a0f6ce0683f28192ac9b3c6e460cacb7818b74ff86fb9e40ab54a0082c6f902204dce5b42e7d31e366cb5115c8e8122288d74e576cb6e74bd7ace0c68fbbd7bf341feffffff02c11b1400000000001976a91464055012df1788e1b290a391ff0122143637e80f88ac00e1f505000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88accc070000";
    var fundingTx = Transaction.fromHex(fundingTxHex);
    var outputAmount = fundingTx.outputs[1].satoshis;
    var fundingOutput = fundingTx.outputs[1];
    var changeAddress = Address.fromPublicKey(privateKey.publicKey, NetworkType.TEST);

    var whitePaper  = await File("${Directory.current.path}/test/data/lorem_ipsum.txt");

      var dataLockBuilder = DataLockBuilder(whitePaper.readAsBytesSync());

    var sighashType = SighashType.SIGHASH_FORKID | SighashType.SIGHASH_ALL;
    var tx = Transaction()
        .spendFromOutput(fundingOutput, Transaction.DEFAULT_SEQNUMBER, scriptBuilder: P2PKHUnlockBuilder(privateKey.publicKey))
        .spendTo(toAddress, BigInt.from(100000), scriptBuilder: P2PKHLockBuilder(toAddress))
        .addDataBuilder(dataLockBuilder)
        .sendChangeTo(changeAddress)
        .withFeePerKb(1000);

        tx.signInput( 0, privateKey, sighashType: sighashType);

      // we then extract the signature from the first input
      var inputIndex = 0;

      var scriptSig = tx.inputs[0].script;
      var scriptPubkey = fundingOutput.script;

      var flags = ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID | ScriptFlags.SCRIPT_ENABLE_MAGNETIC_OPCODES;
      var interpreter = Interpreter();

      var verified = interpreter.verifyScript(scriptSig, scriptPubkey, tx: tx, nin: inputIndex, flags: flags, satoshis: outputAmount );
      expect(interpreter.errstr, equals(""));
      expect(verified, isTrue);

      print(tx.serialize());

  });

  test('generate address', (){
        print(Address.fromPublicKey(privateKey.publicKey, NetworkType.TEST).toBase58());
  });

}


