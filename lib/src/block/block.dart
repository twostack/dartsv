import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'blockheader.dart';

class Block {

    List<Transaction> _transactions;
    BlockHeader _header;

    Block(BlockHeader header, List<Transaction> transactions) {
        this._header = header;
        this._transactions = transactions;
    }


    Block.fromBuffer(List<int> blockbuf) {
        _fromBuffer(blockbuf);
    }

    Block.fromHex(String blockHex) {
        _fromBuffer(HEX.decode(blockHex));
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

    void _fromBuffer(List<int> blockbuf) {
        this._transactions = List<Transaction>();

        if (blockbuf.isEmpty) {
            throw new BlockException('Empty blocks are not allowed');
        }

        ByteDataReader dataReader = ByteDataReader()
            ..add(blockbuf);

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

    get header => this._header;

    get transactions => this._transactions;
}