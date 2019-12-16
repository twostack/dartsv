import 'dart:convert';
import 'dart:io';

import 'package:dartsv/src/block/merkleblock.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

import '../data/merkledata.dart';

void main() {
    String blockhex = MerkleData.HEX[0];
    List<int> blockbuf = HEX.decode(blockhex);
    String blockJSON = jsonEncode(MerkleData.JSON[0]);
    var blockObject = MerkleData.JSON[0];
    var transactionVector = jsonDecode(File("${Directory.current.path}/test/data/tx_creation.json").readAsStringSync());

    group("MerkleBlock", () {
        group('#constructor', () {
            test('should make a new merkleblock from buffer', () {
                var b = MerkleBlock.fromBuffer(blockbuf);
                expect(HEX.encode(b.buffer), equals(blockhex));
            });

            test('should make a new merkleblock from object', () {
                MerkleBlock b = MerkleBlock.fromObject(blockObject);
                expect(b.toObject(), equals(blockObject));
            });

            test('should make a new merkleblock from JSON', () {
                var b = MerkleBlock.fromJSON(blockJSON);
                expect(jsonEncode(b.toObject()), equals(blockJSON));
            });

            test('should not make an empty block', () {
                expect(() => MerkleBlock.fromBuffer([]), throwsException);
                expect(() => MerkleBlock.fromJSON(""), throwsException);
                expect(() => MerkleBlock.fromObject({}), throwsException);
            });
        });


        group('#fromObject', () {
            test('should set these known values', () {
                var block = MerkleBlock.fromObject(jsonDecode(blockJSON));
                expect(block.header, isNotNull);
                expect(block.numTransactions, isNotNull);
                expect(block.hashes, isNotNull);
                expect(block.flags, isNotNull);
            });

            test('should set these known values', () {
                var block = MerkleBlock.fromJSON(blockJSON);
                expect(block.header, isNotNull);
                expect(block.numTransactions, isNotNull);
                expect(block.hashes, isNotNull);
                expect(block.flags, isNotNull);
            });
        });


        group('#toJSON', () {
            test('should recover these known values', () {
                var block = MerkleBlock.fromJSON(blockJSON);
                var b = jsonDecode(block.toJSON());
                expect(block.header, isNotNull);
                expect(block.numTransactions, isNotNull);
                expect(block.hashes, isNotNull);
                expect(block.flags, isNotNull);
                expect(b["header"], isNotNull);
                expect(b["numTransactions"], isNotNull);
                expect(b["hashes"], isNotNull);
                expect(b["flags"], isNotNull);
            });
        });


        group('#fromBuffer', () {
            test('should make a block from this known buffer', () {
                var block = MerkleBlock.fromBuffer(blockbuf);
                expect(HEX.encode(block.buffer), equals(blockhex));
            });
        });


  group('#validMerkleTree', () {
    test('should validate good merkleblocks', () {
      MerkleData.JSON.forEach((data) {
        var b = MerkleBlock.fromObject(data);
        expect(b.validMerkleTree(), isTrue);
      });
    });

    test('should not validate merkleblocks with too many hashes', () {
      var b = MerkleBlock.fromObject(MerkleData.JSON[0]);
      // Add too many hashes
      var i = 0;
      while (i <= b.numTransactions) {
        b.hashes.add('bad' + (i++).toString());
      }
      expect(b.validMerkleTree(), isFalse);
    });

    test('should not validate merkleblocks with too few bit flags', () {
      var b = MerkleBlock.fromObject(jsonDecode(blockJSON));
      b.flags.removeLast();
      expect(b.validMerkleTree(), isFalse);
    });
  });

    });
}

/*
'use strict'

var should = require('chai').should()

var bsv = require('../..')
var MerkleBlock = bsv.MerkleBlock
var BufferReader = bsv.encoding.BufferReader
var BufferWriter = bsv.encoding.BufferWriter
var Transaction = bsv.Transaction
var data = require('../data/merkledata.dart')
var transactionVector = require('../data/tx_creation')

describe('MerkleBlock', function () {




  describe('#filterdTxsHash', function () {
    it('should validate good merkleblocks', function () {
      var hashOfFilteredTx = '6f64fd5aa9dd01f74c03656d376625cf80328d83d9afebe60cc68b8f0e245bd9'
      var b = MerkleBlock(data.JSON[3])
      b.filterdTxsHash()[0].should.equal(hashOfFilteredTx)
    })

    it('should fail with merkleblocks with too many hashes', function () {
      var b = MerkleBlock(data.JSON[0])
      // Add too many hashes
      var i = 0
      while (i <= b.numTransactions) {
        b.hashes.push('bad' + i++)
      }
      (function () {
        b.filterdTxsHash()
      }).should.throw('This MerkleBlock contain an invalid Merkle Tree')
    })

    it('should fail with merkleblocks with too few bit flags', function () {
      var b = MerkleBlock(JSON.parse(blockJSON))
      b.flags.pop();
      (function () {
        b.filterdTxsHash()
      }).should.throw('This MerkleBlock contain an invalid Merkle Tree')
    })
  })

  describe('#hasTransaction', function () {
    it('should find transactions via hash string', function () {
      var jsonData = data.JSON[0]
      var txId = Buffer.from(jsonData.hashes[1], 'hex').toString('hex')
      var b = MerkleBlock(jsonData)
      b.hasTransaction(txId).should.equal(true)
      b.hasTransaction(txId + 'abcd').should.equal(false)
    })

    it('should find transactions via Transaction object', function () {
      var jsonData = data.JSON[0]
      var txBuf = Buffer.from(data.TXHEX[0][0], 'hex')
      var tx = new Transaction().fromBuffer(txBuf)
      var b = MerkleBlock(jsonData)
      b.hasTransaction(tx).should.equal(true)
    })

    it('should not find non-existant Transaction object', function () {
      // Reuse another transaction already in data/ dir
      var serialized = transactionVector[0][7]
      var tx = new Transaction().fromBuffer(Buffer.from(serialized, 'hex'))
      var b = MerkleBlock(data.JSON[0])
      b.hasTransaction(tx).should.equal(false)
    })

    it('should not match with merkle nodes', function () {
      var b = MerkleBlock(data.JSON[0])

      var hashData = [
        ['3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2', false],
        ['019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65', true],
        ['41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068', false],
        ['20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf', false]
      ]

      hashData.forEach(function check (d) {
        b.hasTransaction(d[0]).should.equal(d[1])
      })
    })
  })
})
*/
