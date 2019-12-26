

import 'package:dartsv/dartsv.dart';
import 'encoding/ckdserializer.dart';
import 'package:hex/hex.dart';
import 'crypto/hdutils.dart';
import 'dart:convert';
import 'crypto/childnumber.dart';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'encoding/utils.dart';

/// Provides support for Extended Private keys (__Hierarchical Deterministic__ keys)
/// as described in the [BIP32 spec](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
///
/// This is essentially a method of having a __master private key__, and then using what is generally
/// referred to as a __derivation path__ to generate a *tree* of keypairs which can all be *deterministically*
/// derived from the original __master private key__.
///
/// This method of key generation is useful for enhancing one's privacy by avoiding key re-use.
///
/// ```
///  Extended Private Key Serialization Format
///  =============================================
///
///
///             depth[1]          chaincode[32]
///             \/                  \/
///  |_________|_|________|________________________|________________________|
///    |^              |^                                   |^
///    |^version[4]    |^fingerprint[4]                     |^key[33] <---> privkey(ser256(k))
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
///  33 bytes: 0x00 || ser256(k) for private keys
///
/// ```
class HDPrivateKey extends CKDSerializer{

    final _domainParams = new ECDomainParameters('secp256k1');

    /// Private constructor. Internal use only.
    HDPrivateKey._(NetworkType networkType, KeyType keyType){
        this.networkType = networkType;
        this.keyType = keyType;
    }

    /// Reconstruct a private key from a standard `xpriv` string.
    ///
    HDPrivateKey.fromXpriv(String vector){
        this.networkType = NetworkType.MAIN;
        this.keyType = KeyType.PRIVATE;

        this.deserialize(vector);
    }

    /// Generate a private key from a seed, as described in BIP32
    ///
    HDPrivateKey.fromSeed(String seed, NetworkType networkType) {


        //I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
        var I = HDUtils.hmacSha512WithKey(utf8.encode("Bitcoin seed"), HEX.decode(seed) );

        var masterKey = I.sublist(0, 32);
        var masterChainCode = I.sublist(32,64);

        if (decodeBigInt(masterKey) == BigInt.zero || decodeBigInt(masterKey) > _domainParams.n)
            throw DerivationException("Invalid master key was generated.");

        var paddedKey = Uint8List(33);
        paddedKey[0] = 0;
        paddedKey.setRange(1, 33, Uint8List.fromList(masterKey).toList());

        var dk = HDPrivateKey._(NetworkType.MAIN, KeyType.PRIVATE);
        dk = this._copyParams(dk);

        this.nodeDepth         = 0;
        this.parentFingerprint = List<int>(4)..fillRange(0, 4, 0);
        this.childNumber       = List<int>(4)..fillRange(0, 4, 0);
        this.chainCode         = masterChainCode;
        this.networkType       = networkType;
        this.keyType           = KeyType.PRIVATE;
        this.keyBuffer            = paddedKey;
        this.versionBytes      = getVersionBytes();
    }

    /// Returns the public key associated with this private key
    HDPublicKey get hdPublicKey {
        HDPublicKey hdPublicKey = HDPublicKey.fromXpub(this.xpubkey);
        return hdPublicKey;
    }

    /// Returns the serialized `xpriv`-encoded private key as a string.
    ///
    /// This method is an alias for the [xprivkey] property
    String toString(){
        return this.xprivkey;
    }

    /// Derives a child private key specified by the index
    HDPrivateKey deriveChildNumber(int index) {

        var elem = ChildNumber(index, false);
        var fingerprint = _calculateFingerprint();
        return _deriveChildPrivateKey(this.nodeDepth + 1, Uint8List.fromList(this.keyBuffer), elem, fingerprint, this.chainCode, this.publicKey.getEncoded(true));

    }


    /// Derives a child private key along the specified path
    ///
    /// E.g.
    /// ```
    /// var derived = privateKey.deriveChildKey("m/0'/1/2'");
    /// ```
    ///
    HDPrivateKey deriveChildKey(String path) {
        List<ChildNumber> children =  HDUtils.parsePath(path);


        //some imperative madness to ensure children have their parents' fingerprint
        var fingerprint = _calculateFingerprint();
        var parentChainCode = this.chainCode;
        var lastChild;
        var pubkey = this.publicKey;
        var privkey = this.keyBuffer;
        var nd = 1;
        for (ChildNumber elem in children){
            lastChild = _deriveChildPrivateKey(nd, Uint8List.fromList(privkey), elem, fingerprint, parentChainCode, pubkey.getEncoded(true));
            fingerprint = lastChild._calculateFingerprint();
            parentChainCode = lastChild.chainCode;
            pubkey = lastChild.publicKey;
            privkey = lastChild.keyBuffer;
            nd++;
        }

        return lastChild;

    }


    HDPrivateKey _copyParams(HDPrivateKey hdPrivateKey){

        //all other serializer params should be the same ?
        hdPrivateKey.nodeDepth = this.nodeDepth;
        hdPrivateKey.parentFingerprint = this.parentFingerprint;
        hdPrivateKey.childNumber = this.childNumber;
        hdPrivateKey.chainCode = this.chainCode;
        hdPrivateKey.versionBytes = this.versionBytes;

        return hdPrivateKey;
    }

    List<int> _calculateFingerprint(){
        var normalisedKey = this.keyBuffer.map((elem) => elem.toUnsigned(8));
        var privKey = SVPrivateKey.fromHex(HEX.encode(normalisedKey.toList()), this.networkType);
        var pubKey = SVPublicKey.fromPrivateKey(privKey);
        var encoded = pubKey.getEncoded(true);

        return hash160(HEX.decode(encoded).toList()).sublist(0,4);
    }


    HDPrivateKey _deriveChildPrivateKey(int nd, List<int> privateKey, ChildNumber cn, List<int> fingerprint, List<int> parentChainCode, String pubkey) {

        //TODO: This hoopjumping is irritating. What's the better way ?
        var seriList = List<int>(4);
        seriList.fillRange(0, 4, 0);
        var seriHexVal = HEX.decode(cn.i.toRadixString(16).padLeft(8, "0"));
        seriList.setRange(0, seriHexVal.length, seriHexVal);


        List<int> dataConcat = cn.isHardened() ? privateKey + seriList : HEX.decode(pubkey) + seriList;
        var I = HDUtils.hmacSha512WithKey(Uint8List.fromList(parentChainCode), Uint8List.fromList(dataConcat));

        var lhs = I.sublist(0, 32);
        var chainCode = I.sublist(32,64);
        var normalisedKey = Uint8List.fromList(privateKey);
        var childKey = (BigInt.parse(HEX.encode(lhs), radix: 16) + BigInt.parse(HEX.encode(normalisedKey), radix: 16)) % _domainParams.n;

        var paddedKey = Uint8List(33);
        paddedKey[0] = 0;
        paddedKey.setRange(1, 33, encodeBigInt(childKey));

        var dk = HDPrivateKey._(NetworkType.MAIN, KeyType.PRIVATE);
        dk = this._copyParams(dk);

        dk.nodeDepth = nd;
        dk.parentFingerprint = fingerprint;
        dk.childNumber = seriList;
        dk.chainCode = chainCode;
        dk.keyBuffer = paddedKey;

        return dk;

    }


    HDPublicKey _generatePubKey(){

        HDPublicKey hdPublicKey = new HDPublicKey(this.networkType, KeyType.PUBLIC);

        //ask for a public key
        var pubkey = publicKey;
        hdPublicKey.keyBuffer = HEX.decode(pubkey.getEncoded(true));

        //all other serializer params should be the same ?
        hdPublicKey.nodeDepth =         nodeDepth;
        hdPublicKey.parentFingerprint = parentFingerprint;
        hdPublicKey.childNumber =       childNumber;
        hdPublicKey.chainCode =         chainCode;
        hdPublicKey.versionBytes =      versionBytes;

        return hdPublicKey;
    }

    /// Returns the serialized `xpub`-encoded public key associated with this private key as a string
    String get xpubkey {
        var pubkey = _generatePubKey();

        return pubkey.serialize();
    }

    /// Returns the serialized `xpriv`-encoded private key as a string.
    get xprivkey {
        return this.serialize();
    }

    /// Converts the [HDPrivateKey] instance to a [SVPrivateKey].
    /// The generic APIs require [SVPrivateKey]s, with [HDPrivateKey]
    /// only being used as a means to expose BIP32 wallet functionality
    SVPrivateKey get privateKey  {

        var pk = this.keyBuffer;

        var normalisedPK = pk.map((elem) => elem.toUnsigned(8)).toList();
        return SVPrivateKey.fromHex(HEX.encode(normalisedPK), this.networkType);
    }

    /// Returns the public key associated with this private key as a [SVPublicKey]
    SVPublicKey get publicKey {
        List<int> buffer = this.keyBuffer;

        SVPrivateKey privateKey = SVPrivateKey.fromHex(HEX.encode(Uint8List.fromList(buffer)), this.networkType);

        return privateKey.publicKey;
    }



}
