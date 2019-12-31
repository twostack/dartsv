import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:hex/hex.dart';

/// The BlockHeader contains the metadata for the contents of a block, as well as
/// data describing it's place/position in the blockchain.
///
/// ### The structure of the block header
/// ```
/// 4 bytes - Version - Block version number
/// 32 bytes - hashPrevBlock - sha256 hash of the previous block header
/// 32 bytes - hashMerkleRoot - sha256 hash at the root of a Merkle Tree.
/// 4 bytes - Time - The current block timestamp as seconds since the unix epoch
/// 4 bytes - Bits - The current difficulty target in compact format
/// 4 bytes - Nonce - A 32-bit number (starts at 0)	A hash is tried (increments). A miner would change this field repeatedly as they attempt to generate a hash that matches the difficulty target.
/// ```
///
/// ### Further notes on the block version number. See [Bitcoin.org](https://bitcoin.org/en/developer-reference#block-versions)
/// * __Version 1__ was introduced in the genesis block (January 2009).
///
/// * __Version 2__ was introduced in Bitcoin Core 0.7.0 (September 2012) as a soft fork.
/// As described in BIP34, valid version 2 blocks require a block height /parameter in the coinbase.
/// Also described in BIP34 are rules for rejecting certain blocks; based on those rules, Bitcoin Core 0.7.0
/// and later versions began /to reject version 2 blocks without the block height in coinbase at
/// block height 224,412 (March 2013) and began to reject new version 1 blocks three weeks /later at block height 227,930.
///
/// * __Version 3__ blocks were introduced in Bitcoin Core 0.10.0 (February 2015)
/// as a soft fork. When the fork reached full enforcement (July 2015),
/// it required /strict DER encoding of all ECDSA signatures in new blocks
/// as described in BIP66. Transactions that do not use strict DER encoding
/// had previously been /non-standard since Bitcoin Core 0.8.0 (February 2012).
///
/// * __Version 4__ blocks specified in BIP65 and introduced in Bitcoin Core 0.11.2
/// (November 2015) as a soft fork became active in December 2015. These blocks
/// now support the new OP_CHECKLOCKTIMEVERIFY opcode described in that BIP.
///
class BlockHeader {

    /// Difficulty target at genesis
    static final GENESIS_BITS = 0x1d00ffff;

    /// Byte offset denoting start of the header data structure
    static final START_OF_HEADER = 8; // Start buffer position in raw block data

    /// The max a timestamp can be in the future
    static final MAX_TIME_OFFSET = 2 * 60 * 60;

    /// The largest size a hash value could possibly be
    static final LARGEST_HASH = BigInt.parse('10000000000000000000000000000000000000000000000000000000000000000', radix: 16);

    int _version;
    List<int> _prevHash;
    List<int> _merkleRoot;
    int _time;
    int _bits;
    int _nonce;

    /// Constructs a new block header
    ///
    /// [version] - Block version number
    ///
    /// [prevHash] - sha256 hash of the previous block header
    ///
    /// [merkleRoot] - sha256 hash at the root of the transaction merkle tree
    ///
    /// [time] - the current block timestamp as seconds since the unix epoch
    ///
    /// [bits] - the current difficulty target in compact format
    ///
    /// [nonce] - the nonce field which the miner manipulates repeatedly as they try to find a sha256 hash value that matches the difficulty target
    BlockHeader(this._version, this._prevHash, this._merkleRoot, this._time, this._bits, this._nonce);


    /// Constructs a new block header from it's serialized hexadecimal form
    ///
    /// [blockHeaderHex] - The hexadecimal string containing the block header
    BlockHeader.fromHex(String blockHeaderHex) {
        _parseBuffer(HEX.decode(blockHeaderHex));
    }

    /// Constructs a new block header from it's serialized byte array form
    ///
    /// [buffer] - The byte array containing the block header
    BlockHeader.fromBuffer(List<int> buffer){
        _parseBuffer(buffer);
    }

    /// Constructs a new block header from a raw block. A raw block would include
    /// the first 8 bytes for the *magic number* and *block size* fields
    ///
    /// [dataRawBlockBinary] - The byte array containing the raw block data
    BlockHeader.fromRawBlock(List<int> dataRawBlockBinary) {
        _parseBuffer(dataRawBlockBinary, rawDataRead: true);
    }


    /// Constructs a new block header from a structured object. This would typically
    /// be the result of parsing a JSON string using the dart:convert:jsonXXX API.
    ///
    ///  ### Expected format :
    /// ```json
    ///    {
    ///      "hash":"000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11",
    ///      "version":2,
    ///      "prevHash":"000000003c35b5e70b13d5b938fef4e998a977c17bea978390273b7c50a9aa4b",
    ///      "merkleRoot":"58e6d52d1eb00470ae1ab4d5a3375c0f51382c6f249fff84e9888286974cfc97",
    ///      "time":1371410638,
    ///      "bits":473956288,
    ///      "nonce":3594009557
    ///    }
    /// ```
    ///
    /// [map] - The structured object containing the block data
    BlockHeader.fromJSONMap(LinkedHashMap<String, dynamic> map) {
        this._version = map["version"];
        this._prevHash = HEX
            .decode(map["prevHash"])
            .reversed
            .toList();
        this._merkleRoot = HEX
            .decode(map["merkleRoot"])
            .reversed
            .toList();
        this._time = map["time"];
        this._bits = map["bits"];
        this._nonce = map["nonce"];
    }


    /// Renders/Serializes the block header to a hexadecimal string
    String toHex() {
        return HEX.encode(this.buffer);
    }

    /// Renders/Serializes the block header to a JSON string
    String toJSON() {
        return jsonEncode(toObject());
    }

    /// Renders/Serializes the block header to a structured object
    ///
    /// See [BlockHeader.fromJSONMap()]
    Map<String, dynamic> toObject() {
        return {
            "hash": HEX.encode(this.hash),
            "version": this._version,
            "prevHash": HEX.encode(this._prevHash.reversed.toList()),
            "merkleRoot": HEX.encode(this._merkleRoot.reversed.toList()),
            "time": this._time,
            "bits": this._bits,
            "nonce": this._nonce
        };
    }

    /// Returns *true* if the timestamp is smaller than the [BlockHeader.MAX_TIME_OFFSET], *false* otherwise.
    bool hasValidTimestamp() {
        var currentTime = (new DateTime.now().millisecondsSinceEpoch / 1000).round();
        if (this.time > currentTime + BlockHeader.MAX_TIME_OFFSET) {
            return false;
        }
        return true;
    }

    /// Returns *true* if the sha256 hash of the block header matches the difficulty target, *false* otherwise.
    bool hasValidProofOfWork() {
        var pow = BigInt.parse(this.id, radix: 16);
        var target = this.getTargetDifficulty();

        if (pow.compareTo(target) > 0) {
            return false;
        }
        return true;
    }

    /// Returns current difficulty target or calculates a specific difficulty target.
    ///
    /// [targetBits] - The difficulty target to calculate. If this is *null* the currently set target in the header is returned.
    ///
    /// Returns the difficulty target
    BigInt getTargetDifficulty({int targetBits = null}) {
        if (targetBits == null) {
            targetBits = this._bits;
        }

        BigInt target = BigInt.from(targetBits & 0xffffff);
        var mov = 8 * ((targetBits >> 24) - 3);
        while (mov-- > 0) {
            target = target * BigInt.from(2);
        }
        return target;
    }

    /// Returns the difficulty target of this block header
    double getDifficulty() {

        int nShift = (this._bits >> 24) & 0xff;
        double dDiff = 0x0000ffff / (this._bits & 0x00ffffff);

        while (nShift < 29) {
            dDiff *= 256.0;
            nShift++;
        }
        while (nShift > 29) {
            dDiff /= 256.0;
            nShift--;
        }

        return double.parse(dDiff.toStringAsFixed(8));

    }

    List<int> _calculateHash(List<int> buffer) {
        return sha256Twice(buffer).reversed.toList();
    }

    void _parseBuffer(List<int> buffer, {bool rawDataRead = false}) {
        if (buffer.isEmpty) {
            throw BlockException("Header buffer can't be empty");
        }

        ByteDataReader byteDataReader = ByteDataReader()
            ..add(buffer);

        if (rawDataRead) {
            byteDataReader.read(8); //skip first eight bytes
        }

        this._version = byteDataReader.readInt32(Endian.little);
        this._prevHash = byteDataReader.read(32);
        this._merkleRoot = byteDataReader.read(32);
        this._time = byteDataReader.readUint32(Endian.little);
        this._bits = byteDataReader.readUint32(Endian.little);
        this._nonce = byteDataReader.readUint32(Endian.little);
    }


    /// The block header's *id* is the same as it's [hash] property
    String get id => HEX.encode(this.hash);

    /// The double-sha256 of the serialized block header
    List<int> get hash {
        return _calculateHash(this.buffer);
    }

    /// Returns the block header's nonce value
    int get nonce => _nonce;

    /// Sets this block header's nonce value
    set nonce(int newNonce) {
        this._nonce = newNonce;
    }

    /// Returns the block header's target difficulty
    int get bits => _bits;

    /// Returns the timestamp for this block header. Time is in seconds since unix epoch.
    int get time => _time;

    /// Sets the block header's timestamp.
    set time(int newTime) {
        this._time = newTime;
    }

    /// Returns the block header
    int get version => _version;

    /// Returns the byte buffer representing the sha256 hash of the transaction merkle root
    List<int> get merkleRoot => _merkleRoot;

    /// Returns the sha256 hash of the previous block header
    List<int> get prevHash => _prevHash;

    /// Returns this block header serialized in byte array form
    List<int> get buffer {
        ByteDataWriter writer = ByteDataWriter();

        writer.writeInt32(this._version, Endian.little); //  = byteDataReader.readInt32(Endian.little);
        writer.write(this._prevHash); // = byteDataReader.read(32);
        writer.write(this._merkleRoot); // = byteDataReader.read(32);
        writer.writeUint32(this._time, Endian.little); // = byteDataReader.readUint32(Endian.little);
        writer.writeUint32(this._bits, Endian.little); // = byteDataReader.readUint32(Endian.little);
        writer.writeUint32(this._nonce, Endian.little); // = byteDataReader.readUint32(Endian.little);

        return writer.toBytes().toList();
    }
}