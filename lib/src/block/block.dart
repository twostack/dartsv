import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'blockheader.dart';

class Block {

    static final START_OF_BLOCK = 8; // Start of block in raw block data
    static final NULL_HASH = HEX.decode('0000000000000000000000000000000000000000000000000000000000000000');

    List<Transaction> _transactions;
    BlockHeader _header;

    Block(BlockHeader header, List<Transaction> transactions) {
        this._header = header;
        this._transactions = transactions;
    }

    Block.fromRawBlock(List<int> dataRawBlockBinary) {
        _fromBuffer(dataRawBlockBinary, rawDataRead: true);
    }

    Block.fromBuffer(List<int> blockbuf) {
        _fromBuffer(blockbuf);
    }

    Block.fromHex(String blockHex) {
        _fromBuffer(HEX.decode(blockHex));
    }

    Block.fromObject(Object obj) {
        _parseObject(obj);

    }

    //JSON as decoded using dart:convert:jsonDecode()
    /*
        Expected format :

      {
          "header":{
            "hash":"000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11",
            "version":2,
            "prevHash":"000000003c35b5e70b13d5b938fef4e998a977c17bea978390273b7c50a9aa4b",
            "merkleRoot":"58e6d52d1eb00470ae1ab4d5a3375c0f51382c6f249fff84e9888286974cfc97",
            "time":1371410638,
            "bits":473956288,
            "nonce":3594009557
          },
          "transactions":[]
      }

     */
    Block.fromJSONMap(LinkedHashMap<String, dynamic> map) {
        _parseObject(map);
    }

    _parseObject(map){

        this._transactions = List<Transaction>();

        this._header = BlockHeader.fromJSONMap(map["header"]);

        (map["transactions"] as List).forEach((tx) {
            this._transactions.add(Transaction.fromJSONMap(tx));
        });
    }

    List<int> get buffer {
        ByteDataWriter writer = ByteDataWriter();

        //concatenate all transactions
        List<int> txBuf = this._transactions.fold(<int>[], (List<int> prev, Transaction tx) => prev + HEX.decode(tx.serialize(performChecks: false)));

        writer.write(this._header.buffer);
        writer.write(varIntWriter(this._transactions.length).toList());
        writer.write(txBuf);

        return writer.toBytes().toList();
    }

    /*
        returns the block's hash (header hash) as a buffer
     */
    List<int> get hash => this._header.hash;

    /*
        returns a HEX encoded version of the block's hash
     */
    get id => HEX.encode(this.hash);

    void _fromBuffer(List<int> blockbuf, {bool rawDataRead = false}) {
        this._transactions = List<Transaction>();

        if (blockbuf.isEmpty) {
            throw new BlockException('Empty blocks are not allowed');
        }

        ByteDataReader dataReader = ByteDataReader()
            ..add(blockbuf);

        if (rawDataRead){
            dataReader.read(START_OF_BLOCK); //consume first eight bytes if reading raw data
        }

        var headerBuf = dataReader.read(80);

        this._header = BlockHeader.fromBuffer(headerBuf);


        var txCount = readVarIntNum(dataReader);

        for (var i = 0; i < txCount; i++) {
            this._transactions.add(Transaction.fromBufferReader(dataReader));
        }
    }

    Object toObject(){
       return {
           "header": this._header.toObject(),
           "transactions": this._transactions.map((tx) => tx.toObject()).toList()
       };
    }


    String toHex() {
        return HEX.encode(this.buffer);
    }

    String toJSON() {
        return jsonEncode({
            "header": this._header.toObject(),
            "transactions": this._transactions.map((tx) => tx.toObject()).toList()
        });
    }


    bool validMerkleRoot() {

        var h = BigInt.parse(HEX.encode(this.header.merkleRoot), radix: 16);
        var c = BigInt.parse(HEX.encode(this.getMerkleRoot()), radix: 16);

        if (h != c) {
            return false;
        }

        return true;
    }

    List<int> getMerkleRoot() {
        var tree = this.getMerkleTree();
        return tree[tree.length - 1];
    }

    List<List<int>> getMerkleTree() {

        var tree = this.getTransactionHashes();

        var j = 0;
        for (int size = this.transactions.length; size > 1; size = ((size + 1) / 2).floor()) {
            for (int i = 0; i < size; i += 2) {
                var i2 = min(i + 1, size - 1);
                var buf = tree[j + i] + tree[j + i2];
                tree.add(sha256Twice(buf));
            }
            j += size;
        }

        return tree;
    }

    List<List<int>> getTransactionHashes() {
        List<List<int>> hashes = [];
        if (this.transactions.length == 0) {
            return [Block.NULL_HASH];
        }

        hashes = this.transactions.map((Transaction tx) => tx.hash).toList();

        return hashes;
    }

    BlockHeader get header => this._header;

    List<Transaction> get transactions => this._transactions;

    set transactions(List<Transaction> txns){
        this._transactions = txns;
    }


}