import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:convert';


main() {
    test('should be able to compute sighash for a coinbase tx', () {
        var txhex2 = '02000000013ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a0000000042200000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a010000001976a914a8d9e5fbb49e143db75614dd2189f03f1589727f88ac00000000';
        var txhex = '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2e039b1e1304c0737c5b68747470733a2f2f6769746875622e636f6d2f62636578742f01000001c096020000000000ffffffff014a355009000000001976a91448b20e254c0677e760bab964aec16818d6b7134a88ac00000000';
        var tx = Transaction.fromHex(txhex);
        var sighash = Sighash().hash(tx, SighashType.SIGHASH_ALL, 0, SVScript.fromString(""), BigInt.zero);

        expect(sighash, equals('6829f7d44dfd4654749b8027f44c9381527199f78ae9b0d58ffc03fdab3c82f1'));
    });


    test('bitcoind test vectors for sighash', () async {
        await File("${Directory.current.path}/test/data/sighash.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((vector) {
                //drop the first item

                if (vector.length != 1) {
                    var txbuf = vector[0];
                    var scriptbuf = vector[1];
                    var subscript = SVScript.fromHex(scriptbuf);
                    var nin = vector[2];
                    var nhashtype = vector[3];
                    // var nhashtype = vector[3]>>>0;
                    var sighashbuf = vector[4];
                    var tx = Transaction.fromHex(txbuf);

                    // make sure transaction serialize/deserialize is isomorphic
                    expect(tx.uncheckedSerialize(), equals(txbuf));

                    // sighash ought to be correct
                    expect(Sighash().hash(tx, nhashtype, nin, subscript, BigInt.zero), equals(sighashbuf));
                }

            });
        });
    });


    test('sv-node test vectors for sighash', () async {
        await File("${Directory.current.path}/test/data/sighash-sv.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((vector) {
                //drop the first item

                if (vector.length != 1) {
                    var txbuf = vector[0];
                    var scriptbuf = vector[1];
                    var subscript = SVScript.fromHex(scriptbuf);
                    var nin = vector[2];
                    var nhashtype = vector[3];
                    // var nhashtype = vector[3]>>>0;
                    var sighashbuf = vector[4];
                    var tx = Transaction.fromHex(txbuf);

                    // make sure transaction serialize/deserialize is isomorphic
                    expect(tx.uncheckedSerialize(), equals(txbuf));

                    // sighash ought to be correct
                    expect(Sighash().hash(tx, nhashtype, nin, subscript, BigInt.zero), equals(sighashbuf));
                }

            });
        });
    });
}

//
//    test('Should require amount for sigHash ForkId=0', () {
//        var vector = [
//            '3eb87070042d16f9469b0080a3c1fe8de0feae345200beef8b1e0d7c62501ae0df899dca1e03000000066a0065525365ffffffffd14a9a335e8babddd89b5d0b6a0f41dd6b18848050a0fc48ce32d892e11817fd030000000863acac00535200527ff62cf3ad30d9064e180eaed5e6303950121a8086b5266b55156e4f7612f2c7ebf223e0020000000100ffffffff6273ca3aceb55931160fa7a3064682b4790ee016b4a5c0c0d101fd449dff88ba01000000055351ac526aa3b8223d0421f25b0400000000026552f92db70500000000075253516a656a53c4a908010000000000b5192901000000000652525251516aa148ca38',
//            'acab53',
//            3,
//            -1325231124,
//            'fbbc83ed610e416d94dcee2bb3bc35dfea8060b8052c59eabd7e998e3e978328'
//        ];
//        var txbuf = vector[0];
//        var scriptbuf = HEX.decode(vector[1]);
//        var subscript = SVScript.fromByteArray(scriptbuf);
//        var nin = vector[2];
//        var nhashtype = vector[3];
////        var sighashbuf = vector[4];
//        var tx = Transaction.fromHex(txbuf);
//
//        // make sure transacion to/from buffer is isomorphic
//        expect(tx.uncheckedSerialize(), equals(txbuf.toString()));
//
//        // sighash ought to be correct
//        expect(() => Sighash(tx, nhashtype, nin, subscript).toString(), throwsException);
//    });


