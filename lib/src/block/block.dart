import 'dart:collection';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'blockheader.dart';

class Block {

    List<int> _buffer;
    List<Transaction> _transactions;
    BlockHeader _header;

    Block(BlockHeader header, List<Transaction> transactions) {
        this._header = header;
        this._transactions = transactions;
    }


    Block.fromBuffer(List<int> blockbuf) {

        this._transactions = List<Transaction>();

        if (blockbuf.isEmpty) {
            throw new BlockException('Empty blocks are not allowed');
        }

        this._buffer = blockbuf;

        ByteDataReader dataReader = ByteDataReader()
            ..add(this._buffer);

        var headerBuf = dataReader.read(80);

        this._header = BlockHeader.fromBuffer(headerBuf);


        var txCount = readVarIntNum(dataReader);

        for (var i = 0; i < txCount; i++) {
            this._transactions.add(Transaction.fromBufferReader(dataReader));
        }
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

        (map["transactions"] as List).forEach((tx){
            this._transactions.add(Transaction.fromJSONMap(tx));
        });
    }

    get header => this._header;

    get transactions => this._transactions;

    String toHex() {
        return HEX.encode(this._buffer);
    }


}