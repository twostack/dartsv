                import 'dart:collection';
import 'dart:convert';
import 'dart:math';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'blockheader.dart';

/// A block is the largest of the blockchain's building blocks.
///
/// This is the data structure that miners assemble from transactions,
/// and over which they calculate a sha256 hash
/// as part of their proof-of-work to win the right to extend the blockchain.
///
/// ```
/// 4 bytes | Magic number - value always 0xD9B4BEF9
/// 4 bytes | Blocksize - number of bytes following up to end of block
/// 80 bytes | Block header
/// 1 - 9 bytes | Transaction count. A VarInt containing number of transactions that follow
/// VarByteArray | Transactions - the (non empty) list of transactions
/// ```
///
class Block {

    /// Start of the block in raw block data (discounting magic number and block size bytes)
    static final START_OF_BLOCK = 8;

    /// If the block contains no transactions it must have a null value as it's hash
    static final NULL_HASH = HEX.decode('0000000000000000000000000000000000000000000000000000000000000000');

    List<Transaction>? _transactions;
    BlockHeader? _header;

    /// Constructs a  bitcoin block
    ///
    /// [header] - The block header containing metadata like previous block's id, merkle root etc.
    ///
    /// [transactions] - The list of transactions in this block
    Block(BlockHeader header, List<Transaction> transactions) {
        _header = header;
        _transactions = transactions;
    }

    /// Constructs a  Block instance from a raw byte buffer. A raw byte buffer
    /// has an additional 8 bytes at the beginning that contain the
    /// magic number (4 bytes) and block size (4 bytes)
    ///
    /// [dataRawBlockBinary] - The byte buffer containing the 'raw' block data
    ///
    Block.fromRawBlock(List<int> dataRawBlockBinary) {
        _fromBuffer(dataRawBlockBinary, rawDataRead: true);
    }

    /// Constructs a  Block instance from a byte buffer which already
    /// has the first eight bytes (magic number and block size) stripped out.
    ///
    /// [blockbuf] - The byte buffer containing the block data
    Block.fromBuffer(List<int> blockbuf) {
        _fromBuffer(blockbuf);
    }

    /// Constructs a  Block instance from a hexadecimal string which
    /// has the first eight bytes (magic number and block size) stripped out.
    ///
    /// *NOTE:* This constructor is functionally equivalent to [Block.fromBuffer()] except
    /// that the data is supplied as hex instead of a byte array
    ///
    /// [blockHex] - A hexadecimal string containing the block data
    Block.fromHex(String blockHex) {
        _fromBuffer(HEX.decode(blockHex));
    }

    /// Constructs a  Block from structured data. This constructor is the
    /// functional equivalent of the [Block.fromJSONMap()] constructor.
    ///
    /// ### Expected format :
    ///```
    /// {
    ///     'header':{
    ///         'hash':'000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11',
    ///         'version':2,
    ///         'prevHash':'000000003c35b5e70b13d5b938fef4e998a977c17bea978390273b7c50a9aa4b',
    ///         'merkleRoot':'58e6d52d1eb00470ae1ab4d5a3375c0f51382c6f249fff84e9888286974cfc97',
    ///         'time':1371410638,
    ///         'bits':473956288,
    ///         'nonce':3594009557
    ///    },
    ///    'transactions':[]
    /// }
    ///```
    ///
    /// [obj] - The structured data object
    ///
    Block.fromObject(Map<String, dynamic> obj) {
        _parseObject(obj);

    }

    /// Constructs a  Block from JSON where the block has been decoded into
    /// a LinkedHashMap using dart:convert:jsonDecode(). This is a convenience
    /// constructor for working with JSON. This is
    ///
    ///
    /// ### Expected format :
    ///```
    /// {
    ///     'header':{
    ///         'hash':'000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11',
    ///         'version':2,
    ///         'prevHash':'000000003c35b5e70b13d5b938fef4e998a977c17bea978390273b7c50a9aa4b',
    ///         'merkleRoot':'58e6d52d1eb00470ae1ab4d5a3375c0f51382c6f249fff84e9888286974cfc97',
    ///         'time':1371410638,
    ///         'bits':473956288,
    ///         'nonce':3594009557
    ///    },
    ///    'transactions':[]
    /// }
    ///```
    ///
    /// [jsonData] - The structured JSON data object.
    ///
    Block.fromJSONMap(LinkedHashMap<String, dynamic> jsonData) {
        _parseObject(jsonData);
    }

    /// Renders this block as a structured data object to make
    /// working with JSON representations easy.
    ///
    /// See [Block.fromJSONMap()] for example result data.
    Object toObject(){
        return {
            'header': _header!.toObject(),
            'transactions': _transactions!.map((tx) => tx.toObject()).toList()
        };
    }

    /// Returns the block data as a serialized hexadecimal String.
    String toHex() {
        return HEX.encode(buffer);
    }

    /// Renders this block as a JSON string.
    ///
    /// See [Block.fromJSONMap()] for example result data.
    String toJSON() {
        return jsonEncode({
            'header': _header!.toObject(),
            'transactions': _transactions!.map((tx) => tx.toObject()).toList()
        });
    }

    /// Returns *true* if the transaction hash at the root of the transaction tree
    /// matches the merkle hash in the header. Returns *false* otherwise.
    ///
    /// *NOTE:* Calling this method results in full traversal of all transactions in the block
    /// and the double-sha256 of inner tree nodes to reconstruct the merkle tree. As such it can
    /// be computationally expensive for large blocks especially on memory-constrained devices.
    bool validMerkleRoot() {

        var headerVal = BigInt.parse(HEX.encode(header!.merkleRoot!), radix: 16);
        var transactionVal = BigInt.parse(HEX.encode(getMerkleRoot()), radix: 16);

        if (headerVal != transactionVal ) {
            return false;
        }

        return true;
    }

    /// Retrieves the double-sha256 hash at the base of the transaction merkle tree.
    ///
    /// *NOTE:* Calling this method results in full traversal of all transactions in the block
    /// and the double-sha256 of inner tree nodes to reconstruct the merkle tree. As such it can
    /// be computationally expensive for large blocks especially on memory-constrained devices.
    ///
    /// Returns a byte buffer containing the double-sha256 value representing the 'merkle root'
    List<int> getMerkleRoot() {
        var tree = getMerkleTree();
        return tree[tree.length - 1];
    }

    /// Retrieves the full merkle tree data structure represented by all transactions in the block.
    ///
    /// Returned value is a List of all double-sha256 hashes in the merkle tree. In the absence
    /// of a native Tree datastructure in Dart this is currently represented using the List<> datastructure.
    List<List<int>> getMerkleTree() {
        var tree = getTransactionHashes();

        var j = 0;
        for (var size = transactions!.length; size > 1; size = ((size + 1) / 2).floor()) {
            for (var i = 0; i < size; i += 2) {
                var i2 = min(i + 1, size - 1);
                var buf = tree[j + i] + tree[j + i2];
                tree.add(sha256Twice(buf));
            }
            j += size;
        }

        return tree;
    }

    /// Retrieves the complete list of all Transaction hashes in the block
    List<List<int>> getTransactionHashes() {
        List<List<int>> hashes = [];
        if (transactions!.isEmpty) {
            return [Block.NULL_HASH];
        }

        hashes = transactions!.map((Transaction tx) => tx.hash).toList();

        return hashes;
    }




    void _parseObject(map){

        _transactions = <Transaction>[];

        _header = BlockHeader.fromJSONMap(map['header']);

        (map['transactions'] as List).forEach((tx) {
            _transactions!.add(Transaction.fromJSONMap(tx));
        });
    }

    void _fromBuffer(List<int> blockbuf, {bool rawDataRead = false}) {
        _transactions = <Transaction>[];

        if (blockbuf.isEmpty) {
            throw  BlockException('Empty blocks are not allowed');
        }

        ByteDataReader dataReader = ByteDataReader()
            ..add(blockbuf);

        if (rawDataRead){
            dataReader.read(START_OF_BLOCK); //consume first eight bytes if reading raw data
        }

        var headerBuf = dataReader.read(80);

        _header = BlockHeader.fromBuffer(headerBuf);

        var txCount = readVarIntNum(dataReader);

        for (var i = 0; i < txCount; i++) {
            _transactions!.add(Transaction.fromBufferReader(dataReader));
        }
    }


    /// Returns the full block data as a byte array.
    List<int> get buffer {
        ByteDataWriter writer = ByteDataWriter();

        //concatenate all transactions
        List<int> txBuf = _transactions!.fold(<int>[], (List<int> prev, Transaction tx) => prev + HEX.decode(tx.serialize(performChecks: false)));

        writer.write(_header!.buffer);
        writer.write(varIntWriter(_transactions!.length).toList());
        writer.write(txBuf);

        return writer.toBytes().toList();
    }

    /// Returns the block's hash (header hash) as a buffer
    ///
    List<int> get hash => _header!.hash;

    /// Returns a HEX encoded version of the block's hash
    String get id => HEX.encode(hash);

    /// Returns this block's header as a [BlockHeader] object
    BlockHeader? get header => _header;

    /// Returns this block's transactions a List<[Transaction]>
    List<Transaction>? get transactions => _transactions;

    /// Sets this block's internal list of transactions
    ///
    /// [txns] - The list of transactions with which to populate this block
    set transactions(List<Transaction>? txns){
        _transactions = txns;
    }


}