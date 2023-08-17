import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:convert';
import 'package:hex/hex.dart';


main() {

    test('Should require amount for sigHash ForkId=0', () {
        var vector = [
            '3eb87070042d16f9469b0080a3c1fe8de0feae345200beef8b1e0d7c62501ae0df899dca1e03000000066a0065525365ffffffffd14a9a335e8babddd89b5d0b6a0f41dd6b18848050a0fc48ce32d892e11817fd030000000863acac00535200527ff62cf3ad30d9064e180eaed5e6303950121a8086b5266b55156e4f7612f2c7ebf223e0020000000100ffffffff6273ca3aceb55931160fa7a3064682b4790ee016b4a5c0c0d101fd449dff88ba01000000055351ac526aa3b8223d0421f25b0400000000026552f92db70500000000075253516a656a53c4a908010000000000b5192901000000000652525251516aa148ca38',
            'acab53',
            3,
            -1325231124,
            'fbbc83ed610e416d94dcee2bb3bc35dfea8060b8052c59eabd7e998e3e978328'
        ];
        var txbuf = vector[0];
        var scriptbuf = HEX.decode(vector[1] as String);
        var subscript = SVScript.fromByteArray(scriptbuf as Uint8List);
        var nin = vector[2] as int;
        var nhashtype = vector[3] as int;
        var tx = Transaction.fromHex(txbuf as String);

        // make sure transacion to/from buffer is isomorphic
        expect(tx.serialize(), equals(txbuf.toString()));

        // sighash ought to be correct
        expect(() => Sighash().hash(tx, nhashtype, nin, subscript, null).toString(), throwsException);
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
                    print (txbuf);
                    var scriptbuf = vector[1];
                    var subscript = SVScript.fromHex(scriptbuf);
                    var nin = vector[2];
                    var nhashtype = vector[3] >> 0;
                    // var nhashtype = vector[3]>>>0;
                    var sighashbuf = vector[4];
                    var tx = Transaction.fromHex(txbuf);

                    // make sure transaction serialize/deserialize is isomorphic
                    expect(tx.serialize(), equals(txbuf));

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
                    var nhashtype = vector[3] >> 0;
                    // var nhashtype = vector[3]>>>0;
                    var sighashbuf = vector[4];
                    var tx = Transaction.fromHex(txbuf);

                    // make sure transaction serialize/deserialize is isomorphic
                    expect(tx.serialize(), equals(txbuf));

                    // sighash ought to be correct
                    expect(Sighash().hash(tx, nhashtype, nin, subscript, BigInt.zero), equals(sighashbuf));
                }

            });
        });
    });


}


