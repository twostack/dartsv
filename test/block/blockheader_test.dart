import 'dart:convert';
import 'dart:io';

import 'package:dartsv/src/block/blockheader.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
    int version = 2;
    int time = 1371410638;
    int bits = 473956288;
    int nonce = 3594009557;

    List<int> dataRawBlockBinary = File("${Directory.current.path}/test/data/blk86756-testnet.dat").readAsBytesSync();
    String prevblockIdHex = '4baaa9507c3b27908397ea7bc177a998e9f4fe38b9d5130be7b5353c00000000';
    String merkleRootHex = '97fc4c97868288e984ff9f246f2c38510f5c37a3d5b41aae7004b01e2dd5e658';
    String blockHeaderHex = '020000004baaa9507c3b27908397ea7bc177a998e9f4fe38b9d5130be7b5353c0000000097fc4c97868288e984ff9f246f2c38510f5c37a3d5b41aae7004b01e2dd5e658ce10be51c0ff3f1cd53b38d6';

    group('BlockHeader', () {
        List<int> prevBlockIdBuf = HEX.decode(prevblockIdHex);
        List<int> merkleRootBuf = HEX.decode(merkleRootHex);
        var blockHeader = BlockHeader(version, prevBlockIdBuf, merkleRootBuf, time, bits, nonce);
        var blockHeaderBuf = HEX.decode(blockHeaderHex);

        test('should make a new blockheader', () {
            expect(HEX.encode(BlockHeader
                .fromBuffer(blockHeaderBuf)
                .buffer), equals(blockHeaderHex));
        });


        group('#constructor', () {
            test('should set all the variables', () {
                var bh = BlockHeader(version, prevBlockIdBuf, merkleRootBuf, time, bits, nonce);
                expect(bh.version, isNotNull);
                expect(bh.prevHash, isNotNull);
                expect(bh.merkleRoot, isNotNull);
                expect(bh.time, isNotNull);
                expect(bh.bits, isNotNull);
                expect(bh.nonce, isNotNull);
            });
        });


        group('version', () {
            test('is interpreted as an int32le', () {
                var hex = 'ffffffff00000000000000000000000000000000000000000000000000000000000000004141414141414141414141414141414141414141414141414141414141414141010000000200000003000000';
                var header = BlockHeader.fromBuffer(HEX.decode(hex));
                expect(header.version, equals(-1));
                expect(header.time, equals(1));
            });
        });

        group('#fromRawBlock', () {
            test('should instantiate from a raw block binary', () {
                var x = BlockHeader.fromRawBlock(dataRawBlockBinary);
                expect(x.version, equals(2));
                expect(BigInt.from(x.bits as int).toRadixString(16), equals('1c3fffc0'));
            });
        });


        group('#toJSON', () {
            test('should set all the variables', () {
                var json = jsonDecode(blockHeader.toJSON());
                expect(json["version"], isNotNull);
                expect(json["prevHash"], isNotNull);
                expect(json["merkleRoot"], isNotNull);
                expect(json["time"], isNotNull);
                expect(json["bits"], isNotNull);
                expect(json["nonce"], isNotNull);
            });
        });
    });


    group('#fromJSON', () {
        test('should parse this known json string', () {
            var jsonString = jsonEncode({
                "version": version,
                "prevHash": prevblockIdHex,
                "merkleRoot": merkleRootHex,
                "time": time,
                "bits": bits,
                "nonce": nonce
            });

            var bh = BlockHeader.fromJSONMap(jsonDecode(jsonString));
            expect(bh.version, isNotNull);
            expect(bh.prevHash, isNotNull);
            expect(bh.merkleRoot, isNotNull);
            expect(bh.time, isNotNull);
            expect(bh.bits, isNotNull);
            expect(bh.nonce, isNotNull);
        });
    });


    group('#fromString/#toString', () {
        test('should output/input a block hex string', () {
            var b = BlockHeader.fromHex(blockHeaderHex);
            expect(b.toHex(), equals(blockHeaderHex));
        });
    });


    group('#fromBuffer', () {
        test('should parse this known buffer', () {
            var buf = BlockHeader
                .fromBuffer(HEX.decode(blockHeaderHex))
                .buffer;
            var hexForm = HEX.encode(buf);
            expect(hexForm, equals(blockHeaderHex));
        });
    });


    group('#validTimestamp', () {
        var x = BlockHeader.fromRawBlock(dataRawBlockBinary);

        test('should validate timestamp as true', () {
            var valid = x.hasValidTimestamp();
            expect(valid, isTrue);
        });

        test('should validate timestamp as false', () {
            x.time = (DateTime
                .now()
                .millisecondsSinceEpoch / 1000).round() + BlockHeader.MAX_TIME_OFFSET + 100;
            var valid = x.hasValidTimestamp();
            expect(valid, isFalse);
        });
    });


    group('#validProofOfWork', () {
        test('should validate proof-of-work as true', () {
            var x = BlockHeader.fromRawBlock(dataRawBlockBinary);
            var valid = x.hasValidProofOfWork();
            expect(valid, isTrue);
        });

        test('should validate proof of work as false because incorrect proof of work', () {
            var x = BlockHeader.fromRawBlock(dataRawBlockBinary);
            x.nonce = 0;
            var valid = x.hasValidProofOfWork();
            expect(valid, isFalse);
        });
    });


    group('#getDifficulty', () {
        test('should get the correct difficulty for block 86756', () {
            var x = BlockHeader.fromRawBlock(dataRawBlockBinary);
            expect(x.bits, equals(0x1c3fffc0));
            expect(x.getDifficulty(), equals(4));
        });

        test('should get the correct difficulty for testnet block 552065', () {
            var prevHash = HEX.decode('0000000000001fb81830e9b50a9973b275a843b4158460ac5a5dc53d310c217d');
            var merkleRoot = HEX.decode('8dafcc0119abff36c6dcfcbc0520a6395255d08f792b79ce49173c0de6f5ab62');
            var x = new BlockHeader(
                3,
                prevHash,
                merkleRoot,
                DateTime
                    .parse('2015-09-04 21:26:02')
                    .millisecond,
                0x1b00c2a8,
                163555806
            );

            expect(x.getDifficulty(), equals(86187.62562209));
        });

        test('should get the correct difficulty for livenet block 373043', () {
            var x = new BlockHeader(null, null, null, null, 0x18134dc1, null);
            expect(x.getDifficulty(), equals(56957648455.01001));
        });

        test('should get the correct difficulty for livenet block 340000', () {
            var x = new BlockHeader(null, null, null, null, 0x1819012f, null);
            expect(x.getDifficulty(), equals(43971662056.08958));
        });

        test('should use exponent notation if difficulty is larger than Javascript number', () {
            var x = new BlockHeader(null, null, null, null, 0x0900c2a8, null);
            expect(x.getDifficulty(), equals(1.9220482782645836 * 1e48));
        });
    });

}

