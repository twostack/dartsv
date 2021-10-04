import 'dart:convert';
import 'dart:io';

import 'package:dartsv/src/block/merkleblock.dart';
import 'package:dartsv/src/transaction/transaction.dart';
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
                while (i <= b.numTransactions!) {
                    b.hashes!.add('bad' + (i++).toString());
                }
                expect(b.validMerkleTree(), isFalse);
            });

            test('should not validate merkleblocks with too few bit flags', () {
                var b = MerkleBlock.fromObject(jsonDecode(blockJSON));
                b.flags!.removeLast();
                expect(b.validMerkleTree(), isFalse);
            });
        });

        group('#filterdTxsHash', () {
            test('should return the correct filtered transaction', () {
                var hashOfFilteredTx = '6f64fd5aa9dd01f74c03656d376625cf80328d83d9afebe60cc68b8f0e245bd9';
                var b = MerkleBlock.fromObject(MerkleData.JSON[3]);
                expect(b.filteredTxsHash()[0], equals(hashOfFilteredTx));
            });

            test('should fail with merkleblocks with too many hashes', () {
                var b = MerkleBlock.fromObject(MerkleData.JSON[0]);
                // Add too many hashes
                var i = 0;
                while (i <= b.numTransactions!) {
                    b.hashes!.add('bad' + (i++).toString());
                }
                expect(() => b.filteredTxsHash(), throwsException);
            });

            test('should fail with merkleblocks with too few bit flags', () {
                var b = MerkleBlock.fromJSON(blockJSON);
                b.flags!.removeLast();
                expect(() => b.filteredTxsHash(), throwsException);
            });
        });


        group('#hasTransaction', () {
            test('should find transactions via hash string', () {
                Map<String, dynamic> jsonData = MerkleData.JSON[0];
                var txId = jsonData["hashes"][1];
                var b = MerkleBlock.fromObject(jsonData);
                expect(b.hasTransactionId(txId), equals(true));
                expect(b.hasTransactionId(txId + 'abcd'), equals(false));
            });

            test('should find transactions via Transaction object', () {
                var jsonData = MerkleData.JSON[0];
                var txHex = MerkleData.TXHEX[0][0];
                var tx = Transaction.fromHex(txHex);
                var b = MerkleBlock.fromObject(jsonData);
                expect(b.hasTransaction(tx), equals(true));
            });

            test('should not find non-existent Transaction object', () {
                // Reuse another transaction already in data/ dir
                var serialized = transactionVector[0]["serialize"];
                var tx = Transaction.fromHex(serialized);
                var b = MerkleBlock.fromObject(MerkleData.JSON[0]);
                expect(b.hasTransaction(tx), equals(false));
            });

            test('should not match with merkle nodes', () {
                var b = MerkleBlock.fromObject(MerkleData.JSON[0]);

                var hashData = [
                    ['3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2', false],
                    ['019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65', true],
                    ['41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068', false],
                    ['20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf', false]
                ];

                hashData.forEach((d) {
                    expect(b.hasTransactionId(d[0] as String), equals(d[1]));
                });
            });
        });
    });
}

