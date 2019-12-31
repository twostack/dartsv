import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';

import 'blockheader.dart';

/// A merkle block represents a partial/filtered view of the transactions in a block.
///
/// Because of the way that merkle tree data structures work, it is possible to have a
/// valid data structure which is only partially populated, and to have all the
/// remaining elements in the merkle tree be internally consistent.
///
///
/// ## Data layout of a Merkle Block
///
/// |  size        | description|
/// |--------------| -----------|
/// |  80 bytes    | block header	 - The block header in the format described in [BlockHeader]. |
/// |  4 bytes     | transaction count - The number of transactions in the block (including ones that don’t match the filter)|
/// |  Varies	   | hash count - The number of hashes in the following field. |
/// |  Varies	   | hashes - One or more hashes of both transactions and merkle nodes in internal byte order. Each hash is 32 bytes. |
/// |  Varies	   | flag byte count - The number of flag bytes in the following field. |
/// |  Varies	   | flags - A sequence of bits packed eight in a byte with the least significant bit first. May be padded to the nearest byte boundary but must not contain any more bits than that. Used to assign the hashes to particular nodes in the merkle tree as described below.|
///
///
class MerkleBlock {

    BlockHeader _header;
    int _numTransactions;
    List _hashes;
    List _flags;
    int _flagBitsUsed = 0;
    int _hashesUsed = 0;



    /// Construct a new Merkleblock from the provided structured data object.
    ///
    /// ### Example of structured data for a MerkleBlock
    ///
    /// __Mainnet Block 100014__
    /// ```json
    /// {
    ///     "header": {
    ///     "hash": "000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4",
    ///     "version": 1,
    ///     "prevHash": '0000000000016780c81d42b7eff86974c36f5ae026e8662a4393a7f39c86bb82',
    ///     "merkleRoot": '8772d9d0fdf8c1303c7b1167e3c73b095fd970e33c799c6563d98b2e96c5167f',
    ///     "time": 1293629558,
    ///     "bits": 453281356,
    ///     "nonce": 696601429
    ///   },
    ///   "numTransactions": 7,
    ///   "hashes": [
    ///     '3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2',
    ///     '019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65',
    ///     '41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068',
    ///     '20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf'
    ///   ],
    ///   "flags": [ 29 ]
    /// }
    /// ```
    ///
    /// [blockObject] - Structured data containing the block data
    ///
    MerkleBlock.fromObject(Map<String, dynamic> blockObject) {
        _decodeObject(blockObject);
    }


    /// Construct a Merkle Block from a json string. See [MerkleBlock.fromObject()]
    MerkleBlock.fromJSON(String blockJSON) {
        var obj = jsonDecode(blockJSON);
        _decodeObject(obj);
    }

    /// Construct a Merkle Block from a serialized byte array
    MerkleBlock.fromBuffer(List<int> blockbuf) {
        _parseBuffer(blockbuf);
    }


    /// Renders the Merkle Block as a structured data object
    Map<String, dynamic> toObject() {
        return { // Mainnet Block 100014
            "header": this._header.toObject(),
            "numTransactions": this._numTransactions,
            "hashes": this._hashes,
            "flags": this._flags
        };
    }


    /// Returns *true* if the Merkle tree remains consistent in spite of missing transactions.
    bool validMerkleTree() {
        // Can't have more hashes than numTransactions
        if (this.hashes.length > this.numTransactions) {
            return false;
        }

        // Can't have more flag bits than num hashes
        if (this.flags.length * 8 < this.hashes.length) {
            return false;
        }

        var height = this._calcTreeHeight();
        Map<String, dynamic> resultMap = this._traverseMerkleTree(height, 0, flagBitsUsed: 0);
        if (resultMap["hashesUsed"] != this.hashes.length) {
            return false;
        }
        return HEX.encode(resultMap["nodeValue"]) == HEX.encode(this.header.merkleRoot);
    }


    List<String> filteredTxsHash() {
        // Can't have more hashes than numTransactions
        if (this.hashes.length > this.numTransactions) {
            throw MerkleTreeException("Invalid merkle tree - more hashes than transactions");
        }

        // Can't have more flag bits than num hashes
        if (this.flags.length * 8 < this.hashes.length) {
            throw MerkleTreeException("Invalid merkle tree - more flag bits than hashes");
        }

        // If there is only one hash the filter do not match any txs in the block
        if (this.hashes.length == 1) {
            return [];
        };

        var height = this._calcTreeHeight();
        var hashesUsed = 0, flagBitsUsed = 0;
        var result = this._traverseMerkleTree(height, 0, hashesUsed: hashesUsed, flagBitsUsed: flagBitsUsed, checkForTxs: true);
        if (result["hashesUsed"] != this.hashes.length) {
            throw MerkleTreeException("Invalid merkle tree");
        }
        return result["transactions"];
    }

    /// Returns *true* if the Merkle tree contains the transaction identified by ID
    ///
    /// [txId] - Transaction ID of the transaction we are looking for
    bool hasTransactionId(String txId) {

        //flip and reverse it !
        String hash = txId;  //FIXME: Another place where TransactionID is expected to be reversed and needs flippening. !!!

        List<String> txs = [];
        var height = this._calcTreeHeight();
        _traverseMerkleTree(height, 0, txs: txs );
        return txs.indexOf(hash) != -1;
    }


    /// Returns *true* if the Merkle Tree contains the transaction
    ///
    /// [tx] - The transaction to search for
    bool hasTransaction(Transaction tx) {
        return hasTransactionId(HEX.encode(HEX.decode(tx.id).reversed.toList())); //FIXME: More txId flippening shenanigans. FIX !!!
    }


    void _parseBuffer(List<int> blockbuf) {
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

    Map<String, dynamic> _traverseMerkleTree(
        int depth,
        int pos,
        {
            List<String> txs,
            int hashesUsed = 0,
            int flagBitsUsed = 0,
            bool checkForTxs = false
        }) {

        //FIXME: I hate this, but optional params must be const. A lot of "out" params in this method. Refactor!
        txs = txs == null ? [] : txs;

        if (flagBitsUsed > this.flags.length * 8) {
            return null;
        }

        var isParentOfMatch = (this.flags[flagBitsUsed >> 3] >> (flagBitsUsed++ & 7)) & 1; //fucking magic math *facepalm*
        if (depth == 0 || isParentOfMatch == 0) {
            if (hashesUsed >= this.hashes.length) {
                return null;
            }
            var hash = this.hashes[hashesUsed++];
            if (depth == 0 && isParentOfMatch != 0) {
                txs.add(hash);
            }
            return {"nodeValue" : HEX.decode(hash), "hashesUsed" : hashesUsed, "flagBitsUsed" : flagBitsUsed};
        } else {
            var result = this._traverseMerkleTree(depth - 1, pos * 2, txs: txs, hashesUsed: hashesUsed, flagBitsUsed: flagBitsUsed, checkForTxs: checkForTxs);
            var left = result["nodeValue"];
            hashesUsed = result["hashesUsed"];
            flagBitsUsed = result["flagBitsUsed"];

            var right = left;
            if (pos * 2 + 1 < this._calcTreeWidth(depth - 1)) {
                result = this._traverseMerkleTree(depth - 1, pos * 2 + 1, txs: txs, hashesUsed: hashesUsed, flagBitsUsed: flagBitsUsed, checkForTxs: checkForTxs);
                right = result["nodeValue"];
                hashesUsed = result["hashesUsed"];
                flagBitsUsed = result["flagBitsUsed"];
            }
            if (checkForTxs) {
                return {"transactions" : txs, "hashesUsed": hashesUsed, "flagBitsUsed": flagBitsUsed};
            } else {
                return {"nodeValue" : sha256Twice((left as List<int>) + (right as List<int>)), "hashesUsed" : hashesUsed, "flagBitsUsed" : flagBitsUsed};
            }
        }
    }


    int _calcTreeHeight() {
        var height = 0;
        while (this._calcTreeWidth(height) > 1) {
            height++;
        }
        return height;
    }

    int _calcTreeWidth(int height) {
        return (this.numTransactions + (1 << height) - 1) >> height;
    }

    void _decodeObject(Map<String, dynamic> blockObject) {
        if (!blockObject.containsKey("header") ||
            !blockObject.containsKey("numTransactions") ||
            !blockObject.containsKey("flags") ||
            !blockObject.containsKey("hashes")) {
            throw BlockException("Object is only partially constructed. I can't help you. ");
        }

        var headerObj = blockObject["header"];
        this._header = BlockHeader(
            headerObj["version"],
            HEX
                .decode(headerObj["prevHash"])
                .reversed
                .toList(),
            HEX
                .decode(headerObj["merkleRoot"])
                .reversed
                .toList(),
            headerObj["time"],
            headerObj["bits"],
            headerObj["nonce"]
        );

        this._numTransactions = blockObject["numTransactions"];
        this._hashes = blockObject["hashes"];
        this._flags = blockObject["flags"];
    }

    /// Returns the merkle block serialized as a byte array
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

    /// Returns the bit-packed data structure showing locations of hashes in the tree
    List get flags => _flags;

    /// A list of all the hashes in the merkle block
    List get hashes => _hashes;

    /// Total transaction count for the block. Includes transactions not in the block.
    int get numTransactions => _numTransactions;

    /// Returns the block header
    BlockHeader get header => _header;

    /// Serializes the Merkle Block to a JSON string
    String toJSON() {
        return jsonEncode(toObject());
    }





}