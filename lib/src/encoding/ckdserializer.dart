
import '../networks.dart';
import 'package:hex/hex.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'base58check.dart' as bs58check;
import 'utils.dart' as utils;



abstract class CKDSerializer {

    static final List<int> MAINNET_PUBLIC  = HEX.decode("0488B21E");
    static final List<int> MAINNET_PRIVATE = HEX.decode("0488ADE4");
    static final List<int> TESTNET_PUBLIC  = HEX.decode("043587CF");
    static final List<int> TESTNET_PRIVATE = HEX.decode("04358394");

    int _nodeDepth;
    List<int> _parentFingerprint = List(4); //Uint32
    List<int> _childNumber = List(4);       //Uint32
    List<int> _chainCode = List(32);        //Uint8List(32)
    List<int> _keyHex = List(33);           //Uint8List(33)
    List<int> _versionBytes = List(4);      //Uint32
    NetworkType _networkType;
    KeyType _keyType;


    void deserialize(String vector){

        List<int> decoded = bs58check.decodeChecked(vector);

        this._versionBytes = decoded.sublist(0, 4);
        this._nodeDepth = decoded[4];
        this._parentFingerprint = decoded.sublist(5, 9);
        this._childNumber = decoded.sublist(9, 13);
        this._chainCode   = decoded.sublist(13, 45);
        this._keyHex   = decoded.sublist(45, 78);

        var version = HEX.encode(this._versionBytes.map( (elem) => elem.toUnsigned(8) ).toList());

    }

    // FIXME: Rewrite using the Buffer class
    String serialize(){

        var versionBytes =   getVersionBytes();

        var depth = this._nodeDepth;
        var fingerprint = this._parentFingerprint;
        var chainCode = this._chainCode;
        var pubkeyHex = this._keyHex;

        List<int> serializedKey = List(78);
        serializedKey.setRange(0, 4, versionBytes);
        serializedKey.setRange(4, 5, [this._nodeDepth]);
        serializedKey.setRange(5, 9, this._parentFingerprint);
        serializedKey.setRange(9, 13,this._childNumber);
        serializedKey.setRange(13, 45,this._chainCode);
        serializedKey.setRange(45, 78,this._keyHex);

        //checksum calculation... doubleSha
        var doubleShaAddr = utils.sha256Twice(serializedKey);
        var checksum = doubleShaAddr.sublist(0, 4).map((elem) => elem.toSigned(8)).toList();

        List<int> encoded = bs58check.encode(serializedKey + checksum);

        return utf8.decode(encoded);
    }

    List<int> getVersionBytes() {

        switch (this._networkType){
            case NetworkType.MAIN:  {
                return this._keyType == KeyType.PUBLIC ? MAINNET_PUBLIC : MAINNET_PRIVATE;
            }
            case NetworkType.REGTEST:
            case NetworkType.SCALINGTEST:
            case NetworkType.TEST:  {
                return this._keyType == KeyType.PUBLIC ? TESTNET_PUBLIC : TESTNET_PRIVATE;
            }
            default: {
                return this._keyType == KeyType.PUBLIC ? TESTNET_PUBLIC : TESTNET_PRIVATE;
            }
        }
    }

    set chainCode(List<int> bytes) {
        this._chainCode = bytes;
    }


    NetworkType get networkType => _networkType;

    set networkType(NetworkType value) {
        _networkType = value;
    }

    List<int> get chainCode {
        return this._chainCode; 
    }

    /// Initialize the key from a byte buffer
    ///
    /// `bytes` - Hexadecimal version of key encoded as a byte buffer
    set keyBuffer(List<int> bytes) {
        this._keyHex = bytes;
    }

    /// Retrieves the key as a byte buffer
    ///
    List<int> get keyBuffer {
       return Uint8List.fromList(this._keyHex).toList();
    }

    set versionBytes(List<int> bytes) {
        this._versionBytes = bytes;
    }

    List<int> get versionBytes{
        return this._versionBytes;
    }

    set nodeDepth(int depth) {
        this._nodeDepth = depth;
    }

    int get nodeDepth {
        return this._nodeDepth;
    }

    set parentFingerprint(List<int> bytes) {
        this._parentFingerprint = bytes;
    }

    List<int> get parentFingerprint{
        return this._parentFingerprint;
    }

    set childNumber(List<int> bytes) {
        this._childNumber = bytes;
    }

    List<int> get childNumber {
        return this._childNumber;
    }

    KeyType get keyType => _keyType;

    set keyType(KeyType value) {
        _keyType = value;
    }




}