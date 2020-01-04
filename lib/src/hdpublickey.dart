

import 'package:twostack/src/hdprivatekey.dart';
import 'package:twostack/src/networks.dart';
import 'package:twostack/src/publickey.dart';

import 'encoding/ckdserializer.dart';
import 'package:hex/hex.dart';
import 'crypto/hdutils.dart';
import 'crypto/childnumber.dart';
import 'encoding/utils.dart';
import 'dart:typed_data';
import 'exceptions.dart';
import 'privatekey.dart';
import 'package:pointycastle/pointycastle.dart';

/// Provides support for Extended Public keys (__Hierarchical Deterministic__ keys)
/// as described in the [BIP32 spec](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
///
/// Additional child pubkeys can be derived from this, but no further private keys can be directly derived.
///
/// ```
///  Extended PubKey Serialization Format
///  =============================================
///
///
///             depth[1]          chaincode[32]
///             \/                  \/
///  |_________|_|________|________________________|________________________|
///    |^              |^                                   |^
///    |^version[4]    |^fingerprint[4]                     |^key[33] <---> pubkey(serP(K))
///
///  4 bytes: version bytes (
///              mainnet:
///                      public: 0x0488B21E ,
///                      private: 0x0488ADE4 ;
///              testnet:
///                      public: 0x043587CF ,
///                      private: 0x04358394 )
///
///  1 byte:
///      depth: 0x00 for master nodes,
///             0x01 for level-1 derived keys, ....
///
///  4 bytes: the fingerprint of the parent key (0x00000000 if master key)
///  4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
///  32 bytes: the chain code
///  33 bytes: the public key (serP(K) for public keys
///
/// ```
class HDPublicKey extends CKDSerializer {
    final _domainParams = new ECDomainParameters('secp256k1');

    String _publicVector;
    HDPrivateKey _hdPrivateKey;

    /// Private constructor. Internal use only.
    HDPublicKey._(NetworkType networkType, KeyType keyType){
        this.networkType = networkType;
        this.keyType = keyType;
    }

    /// Constructs a public key from it's matching HD private key parameters
    HDPublicKey(
        SVPublicKey publicKey,
        NetworkType networkType,
        int nodeDepth,
        List<int> parentFingerprint,
        List<int> childNumber,
        List<int> chainCode,
        List<int> versionBytes){

        this.nodeDepth =         nodeDepth;
        this.parentFingerprint = parentFingerprint;
        this.childNumber =       childNumber;
        this.chainCode =         chainCode;
        this.versionBytes =      versionBytes;
        this.keyType = KeyType.PUBLIC;
        this.networkType = networkType;
        this.keyBuffer = HEX.decode(publicKey.getEncoded(true));
    }

    /// Constructs a new public key from it's `xpub`-encoded representation
    HDPublicKey.fromXpub(String vector){
        this.networkType = NetworkType.MAIN;
        this.keyType = KeyType.PUBLIC;
        deserialize(vector);
        this._publicVector = vector;
    }

    /// Renders the public key in it's `xpub`-encoded form
    String toString(){
        return this.xpubkey;
    }

    /// Derive a new child public key at `index`
    HDPublicKey deriveChildNumber(int index) {
        var elem = ChildNumber(index, false);
        var fingerprint = _calculateFingerprint();
        var pubkey = HEX.encode(Uint8List.fromList(this.keyBuffer).toList());
        return _deriveChildPublicKey(this.nodeDepth, elem, fingerprint, this.chainCode, pubkey);
    }

    /// Derive a new child public key using the indicated path
    ///
    /// E.g.
    /// ```
    /// var derived = publicKey.deriveChildKey("m/0/1/2");
    /// ```
    HDPublicKey deriveChildKey(String path) {

        List<ChildNumber> children =  HDUtils.parsePath(path);

        //some imperative madness to ensure children have their parents' fingerprint
        var fingerprint = _calculateFingerprint();
        var parentChainCode = this.chainCode;
        var lastChild;
        var pubkey = HEX.encode(Uint8List.fromList(this.keyBuffer).toList());
        var nd = nodeDepth;
        for (ChildNumber elem in children){

            if (elem.isHardened())
                throw DerivationException("Can't derived hardened public keys without private keys");

            lastChild = _deriveChildPublicKey(nd, elem, fingerprint, parentChainCode, pubkey);
            fingerprint = lastChild._calculateFingerprint();
            parentChainCode = lastChild.chainCode;
            pubkey = HEX.encode(lastChild.keyBuffer);
            nd++;

        }

        return lastChild;

    }

    List<int> _calculateFingerprint(){
        var normalisedKey = this.keyBuffer.map((elem) => elem.toUnsigned(8));
        var pubKey = SVPublicKey.fromHex(HEX.encode(normalisedKey.toList()));
        var encoded = pubKey.getEncoded(true);

        return hash160(HEX.decode(encoded).toList()).sublist(0,4);
    }

    HDPublicKey _deriveChildPublicKey(int nd, ChildNumber cn, List<int> fingerprint, List<int> parentChainCode, String pubkey) {

        //TODO: This hoopjumping is irritating. What's the better way ?
        var seriList = List<int>(4);
        seriList.fillRange(0, 4, 0);
        var seriHexVal = HEX.decode(cn.i.toRadixString(16).padLeft(8, "0"));
        seriList.setRange(0, seriHexVal.length, seriHexVal);

        List<int> dataConcat = HEX.decode(pubkey) + seriList;
        var I = HDUtils.hmacSha512WithKey(Uint8List.fromList(parentChainCode), Uint8List.fromList(dataConcat));

        var lhs = I.sublist(0, 32);
        var chainCode = I.sublist(32,64);

        var parentPoint = _domainParams.curve.decodePoint(HEX.decode(pubkey));
        var privateKey = SVPrivateKey.fromHex(HEX.encode(lhs), this.networkType);
        var pubKeyHex = HEX.decode(privateKey.publicKey.getEncoded(true));
        var thisPoint = _domainParams.curve.decodePoint(pubKeyHex);
        var derivedPoint = thisPoint + parentPoint;

        //TODO: Validate that the point is on the curve !

        var dk = HDPublicKey._(NetworkType.MAIN, KeyType.PUBLIC);
        dk = this._copyParams(dk);

        dk.nodeDepth = nd + 1;
        dk.parentFingerprint = fingerprint;
        dk.childNumber = seriList;
        dk.chainCode = chainCode;
        dk.keyBuffer = derivedPoint.getEncoded(true);

        return dk;

    }


    HDPublicKey _copyParams(HDPublicKey hdPublicKey){

        //all other serializer params should be the same ?
        hdPublicKey.nodeDepth = this.nodeDepth;
        hdPublicKey.parentFingerprint = this.parentFingerprint;
        hdPublicKey.childNumber = this.childNumber;
        hdPublicKey.chainCode = this.chainCode;
        hdPublicKey.versionBytes = this.versionBytes;

        return hdPublicKey;
    }

    /// Returns the serialized representation of the extended public key.
    ///
    ///    4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
    ///    1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    ///    4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    ///    4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    ///    32 bytes: the chain code
    ///    33 bytes: the public key data ( serP(K) )
    ///
    String get xpubkey {
        return serialize();
    }



}