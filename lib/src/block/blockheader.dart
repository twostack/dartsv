import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:hex/hex.dart';

class BlockHeader {

    static final GENESIS_BITS = 0x1d00ffff;

    static final START_OF_HEADER = 8; // Start buffer position in raw block data
    static final MAX_TIME_OFFSET = 2 * 60 * 60; // The max a timestamp can be in the future
    static final LARGEST_HASH = BigInt.parse('10000000000000000000000000000000000000000000000000000000000000000', radix: 16);

    int _version;
    List<int> _prevHash;
    List<int> _merkleRoot;
    int _time;
    int _bits;
    int _nonce;

    BlockHeader(this._version, this._prevHash, this._merkleRoot, this._time, this._bits, this._nonce);


    BlockHeader.fromHex(String blockHeaderHex) {
        _parseBuffer(HEX.decode(blockHeaderHex));
    }

    BlockHeader.fromBuffer(List<int> buffer){
        _parseBuffer(buffer);
    }


    BlockHeader.fromRawBlock(List<int> dataRawBlockBinary) {
        _parseBuffer(dataRawBlockBinary, rawDataRead: true);
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

    /*
        Expected format :

          {
            "hash":"000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11",
            "version":2,
            "prevHash":"000000003c35b5e70b13d5b938fef4e998a977c17bea978390273b7c50a9aa4b",
            "merkleRoot":"58e6d52d1eb00470ae1ab4d5a3375c0f51382c6f249fff84e9888286974cfc97",
            "time":1371410638,
            "bits":473956288,
            "nonce":3594009557
          }
     */
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


    String toHex() {
        return HEX.encode(this.buffer);
    }


    String toJSON() {
        return jsonEncode(toObject());
    }

    Object toObject() {
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

    List<int> _calculateHash(List<int> buffer) {
        return sha256Twice(buffer).reversed.toList();
    }

    String get id => HEX.encode(this.hash);

    List<int> get hash {
        return _calculateHash(this.buffer);
    }

    int get nonce => _nonce;

    set nonce(int newNonce) {
        this._nonce = newNonce;
    }

    int get bits => _bits;

    int get time => _time;

    set time(int newTime) {
        this._time = newTime;
    }

    int get version => _version;

    List<int> get merkleRoot => _merkleRoot;

    List<int> get prevHash => _prevHash;


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

    bool hasValidTimestamp() {
        var currentTime = (new DateTime.now().millisecondsSinceEpoch / 1000).round();
        if (this.time > currentTime + BlockHeader.MAX_TIME_OFFSET) {
            return false;
        }
        return true;
    }

    bool hasValidProofOfWork() {
        var pow = BigInt.parse(this.id, radix: 16);
        var target = this.getTargetDifficulty();

        if (pow.compareTo(target) > 0) {
            return false;
        }
        return true;
    }

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


}