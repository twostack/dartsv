import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:hex/hex.dart';

import 'blockheader.dart';

class MerkleBlock {

    BlockHeader _header;
    int _numTransactions;
    List _hashes;
    List _flags;
    int _flagBitsUsed = 0;
    int _hashesUsed = 0;


    /*

    { // Mainnet Block 100014
        "header": {
        "hash": "000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4",
        "version": 1,
        "prevHash": '0000000000016780c81d42b7eff86974c36f5ae026e8662a4393a7f39c86bb82',
        "merkleRoot": '8772d9d0fdf8c1303c7b1167e3c73b095fd970e33c799c6563d98b2e96c5167f',
        "time": 1293629558,
        "bits": 453281356,
        "nonce": 696601429
      },
      "numTransactions": 7,
      "hashes": [
        '3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2',
        '019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65',
        '41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068',
        '20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf'
      ],
      "flags": [ 29 ]
    },
   */
    MerkleBlock.fromObject(Map<String, dynamic> blockObject) {
        _decodeObject(blockObject);
    }

    void _decodeObject(Map<String, dynamic> blockObject){

        if ( !blockObject.containsKey("header") ||
             !blockObject.containsKey("numTransactions")  ||
             !blockObject.containsKey("flags") ||
             !blockObject.containsKey("hashes") ){
            throw BlockException("Object is only partially constructed. I can't help you. ");
        }

        var headerObj = blockObject["header"];
        this._header = BlockHeader(
            headerObj["version"],
            HEX.decode(headerObj["prevHash"]).reversed.toList(),   //FIXME: I have the feeling this won't always be a String needing decoding
            HEX.decode(headerObj["merkleRoot"]).reversed.toList(),
            headerObj["time"],
            headerObj["bits"],
            headerObj["nonce"]
        );

        this._numTransactions = blockObject["numTransactions"];
        this._hashes = blockObject["hashes"];
        this._flags = blockObject["flags"];
    }


    MerkleBlock.fromJSON(String blockJSON) {
        var obj = jsonDecode(blockJSON);
        _decodeObject(obj);
    }

    MerkleBlock.fromBuffer(List<int> blockbuf) {
        _parseBuffer(blockbuf);
    }

    void _parseBuffer(List<int> blockbuf){

        ByteDataReader reader = ByteDataReader();
        reader.add(blockbuf);

        if (reader.remainingLength == 0) {
            throw BlockException("No remaining merkle data to read");
        }

        this._header = BlockHeader.fromBuffer(reader.read(80));
        this._numTransactions = reader.readUint32(Endian.little);
        var numHashes = readVarIntNum(reader);
        this._hashes = [];

        for (var i = 0; i < numHashes; i++) {
            this._hashes.add(HEX.encode(reader.read(32)));
        }

        var numFlags = readVarIntNum(reader);
        this._flags = [];
        for (int i = 0; i < numFlags; i++) {
            this._flags.add(reader.readUint8());
        }
    }

    Map<String, dynamic> toObject() {
        return { // Mainnet Block 100014
            "header": this._header.toObject(),
            "numTransactions": this._numTransactions,
            "hashes": this._hashes,
            "flags": this._flags
        };
    }

    List<int> get buffer {
        ByteDataWriter writer = ByteDataWriter();

        writer.write(this._header.buffer);
        writer.writeUint32(this._numTransactions, Endian.little);
        writer.write(varIntWriter(this._hashes.length));

        for (int i = 0; i < this._hashes.length; i++) {
            writer.write(HEX.decode(this._hashes[i]));
        }

        writer.write(varIntWriter(this._flags.length));
        for (int i = 0; i < this._flags.length; i++) {
            writer.writeUint8(this._flags[i]);
        }

        return writer.toBytes().toList();
    }

    List get flags => _flags;

    List get hashes => _hashes;

    int get numTransactions => _numTransactions;

    BlockHeader get header => _header;

}