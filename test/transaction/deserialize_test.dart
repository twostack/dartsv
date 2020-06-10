import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:convert';

main(){

    test('Transaction deserialization', () async {
        await File("${Directory.current.path}/test/data/bitcoind/tx_valid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
                var ndx = 0;
            List.from(jsonData).forEach((item) {
                //FIXME: Right now this test has ONE case which is not P2SH
                if (item.length > 1 && !item[2].toString().contains("P2SH")) {

                    var txn = Transaction.fromHex(item[1]);
                    ndx++;

                    var outNdx = 0;
                    txn.outputs.forEach((txnOut){

                        var prevHash     = item[0][outNdx][0]; //prev out hash
                        var prevOutIndex = item[0][outNdx][1]; //prev out index
                        var prevOutSPK   = item[0][outNdx][2]; //prev out script pubkey
                        expect(prevHash, equals(txn.inputs[outNdx].prevTxnId));
                        expect(prevOutIndex, equals(txn.inputs[outNdx].prevTxnOutputIndex));
//                        expect(prevOutSPK, equals(txn.inputs[outNdx].script.toHex()));

                        outNdx++;
                    });
                }

            });
        });
    });

}
/*
var Transaction = require('../../lib/transaction')

var vectorsValid = require('../data/bitcoind/tx_valid.json')
var vectorsInvalid = require('../data/bitcoind/tx_invalid.json')

describe('Transaction deserialization', function () {
  describe('valid transaction test case', function () {
    var index = 0
    vectorsValid.forEach(function (vector) {
      it('vector #' + index, function () {
        if (vector.length > 1) {
          var hexa = vector[1]
          Transaction(hexa).serialize(true).should.equal(hexa)
          index++
        }
      })
    })
  })
  describe('invalid transaction test case', function () {
    var index = 0
    vectorsInvalid.forEach(function (vector) {
      it('invalid vector #' + index, function () {
        if (vector.length > 1) {
          var hexa = vector[1]
          Transaction(hexa).serialize(true).should.equal(hexa)
          index++
        }
      })
    })
  })
})

*/
