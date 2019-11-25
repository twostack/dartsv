

import 'package:dartsv/dartsv.dart';
import 'encoding/ckdserializer.dart';
import 'package:hex/hex.dart';
import 'crypto/hdutils.dart';
import 'dart:convert';
import 'crypto/childnumber.dart';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'encoding/utils.dart';

class HDPrivateKey extends CKDSerializer{

//    Map<String, HDPrivateKey> _cache  = new HashMap();

    String _privateVector;
//    final CKDSerializer _ckdSerializer = new CKDSerializer(NetworkType.MAIN, KeyType.PRIVATE);
    final _domainParams = new ECDomainParameters('secp256k1');

    HDPrivateKey(NetworkType networkType, KeyType keyType){
        this.networkType = networkType;
        this.keyType = keyType;
    }

    HDPrivateKey.fromXpriv(String vector){
        this.networkType = NetworkType.MAIN;
        this.keyType = KeyType.PRIVATE;

        this.deserialize(vector);
        this._privateVector = vector;
    }

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

        var dk = new HDPrivateKey(NetworkType.MAIN, KeyType.PRIVATE);
        dk = this._copyParams(dk);

        this.nodeDepth         = 0;
        this.parentFingerprint = List<int>(4)..fillRange(0, 4, 0);
        this.childNumber       = List<int>(4)..fillRange(0, 4, 0);
        this.chainCode         = masterChainCode;
        this.networkType       = networkType;
        this.keyType           = KeyType.PRIVATE;
        this.keyHex            = paddedKey;
        this.versionBytes      = getVersionBytes();
    }

    HDPublicKey get hdPublicKey {
        HDPublicKey hdPublicKey = HDPublicKey.fromXpub(this.xpubkey);
        return hdPublicKey;
    }


    String toString(){
        return this.xprivkey;
    }

    get xprivkey {
        return this.serialize();
    }
    
    SVPrivateKey get privateKey  {

        var pk = this.keyHex;

        var normalisedPK = pk.map((elem) => elem.toUnsigned(8)).toList();
        return SVPrivateKey.fromHex(HEX.encode(normalisedPK), this.networkType);
    }

    //FIXME: Refactor this lame Uint8List conversion
    String get publicKey {
        var pk = this.keyHex;

        var normalisedPK = pk.map((elem) => elem.toUnsigned(8)).toList();
        SVPrivateKey privateKey = SVPrivateKey.fromHex(HEX.encode(normalisedPK), this.networkType);

        return privateKey.publicKey.getEncoded(true);
    }

    HDPrivateKey _instanceFromPK(SVPrivateKey privkey){
        var hdPrivateKey = new HDPrivateKey(NetworkType.MAIN, KeyType.PRIVATE);
        hdPrivateKey.keyHex = HEX.decode(privkey.toHex());
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
        var normalisedKey = this.keyHex.map((elem) => elem.toUnsigned(8));
        var privKey = SVPrivateKey.fromHex(HEX.encode(normalisedKey.toList()), this.networkType);
        var pubKey = SVPublicKey.fromPrivateKey(privKey);
        var encoded = pubKey.getEncoded(true);

        return hash160(HEX.decode(encoded).toList()).sublist(0,4);
    }


    HDPrivateKey deriveChildNumber(int index) {

        var elem = ChildNumber(index, false);
        var fingerprint = _calculateFingerprint();
        return _deriveChildPrivateKey(this.nodeDepth + 1, Uint8List.fromList(this.keyHex), elem, fingerprint, this.chainCode, this.publicKey);

    }

    HDPrivateKey deriveChildKey(String path) {

        //look in current cache for previously derived child
//        if (this._cache.containsKey(path)) {
//            return this._cache[path];
//        }

        List<ChildNumber> children =  HDUtils.parsePath(path);


        //some imperative madness to ensure children have their parents' fingerprint
        var fingerprint = _calculateFingerprint();
        var parentChainCode = this.chainCode;
        var lastChild;
        var pubkey = this.publicKey;
        var privkey = this.keyHex;
        var nd = 1;
        for (ChildNumber elem in children){
            lastChild = _deriveChildPrivateKey(nd, Uint8List.fromList(privkey), elem, fingerprint, parentChainCode, pubkey);
            fingerprint = lastChild._calculateFingerprint();
            parentChainCode = lastChild.chainCode;
            pubkey = lastChild.publicKey;
            privkey = lastChild.keyHex;
            nd++;
        }

        return lastChild;

//        this._cache[path] = ck;

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

        var dk = new HDPrivateKey(NetworkType.MAIN, KeyType.PRIVATE);
        dk = this._copyParams(dk);

        dk.nodeDepth = nd;
        dk.parentFingerprint = fingerprint;
        dk.childNumber = seriList;
        dk.chainCode = chainCode;
        dk.keyHex = paddedKey;

        return dk;

    }

    String get xpubkey {
        var pubkey = _generatePubKey();

        return pubkey.serialize();
    }

    HDPublicKey _generatePubKey(){

        HDPublicKey hdPublicKey = new HDPublicKey(this.networkType, KeyType.PUBLIC);

        //ask for a public key
        var pubkey = publicKey;
        hdPublicKey.keyHex = HEX.decode(pubkey);

        //all other serializer params should be the same ?
        hdPublicKey.nodeDepth =         nodeDepth;
        hdPublicKey.parentFingerprint = parentFingerprint;
        hdPublicKey.childNumber =       childNumber;
        hdPublicKey.chainCode =         chainCode;
        hdPublicKey.versionBytes =      versionBytes;

        return hdPublicKey;
    }



}
