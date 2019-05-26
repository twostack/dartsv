import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/networks.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'encoding/base58check.dart' as bs58check;
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'encoding/utils.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";
import 'package:pointycastle/api.dart';


class SVPrivateKey {

    final _domainParams = new ECDomainParameters('secp256k1');
    final _secureRandom = new FortunaRandom();

    var _hasCompressedPubKey = false;
    var _networkType = NetworkType.MAIN; //Mainnet by default

    var random = new Random.secure();

    BigInt _d;
    ECPrivateKey _ecPrivateKey;
    SVPublicKey _ecPublicKey;

    //by default creates random Private Key
    SVPrivateKey({networkType: NetworkType.MAIN}) {
        var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
        _secureRandom.seed(KeyParameter(_seed()));

        var generator = ECKeyGenerator();
        generator.init(ParametersWithRandom(keyParams, _secureRandom));

        var keypair = generator.generateKeyPair();

        this._hasCompressedPubKey = true;
        this._networkType = networkType;

        this._ecPrivateKey = keypair.privateKey;
        this._d = this._ecPrivateKey.d;
        this._ecPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    Uint8List _seed() {
        var random = Random.secure();
        var seed = List<int>.generate(32, (_) => random.nextInt(256));
        return Uint8List.fromList(seed);
    }

    SVPrivateKey.fromBigInt(BigInt d){
        this._ecPrivateKey = _privateKeyFromBigInt(d);
        this._d = d;
        this._ecPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    SVPrivateKey.fromHex(String privhex, NetworkType networkType) {
        var d = BigInt.parse(privhex,radix: 16);

        this._hasCompressedPubKey = true;
        this._networkType = networkType;
        this._ecPrivateKey = _privateKeyFromBigInt(d);
        this._d = d;
        this._ecPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    SVPrivateKey.fromWIF(String knownKey){

        if (knownKey.length != 51 && knownKey.length != 52){
            throw new InvalidKeyException("Valid keys are either 51 or 52 bytes in length");
        }

       //decode from base58
        List<int> versionAndDataBytes = bs58check.decodeChecked(knownKey);


        switch (knownKey[0]){
            case "5" : {
                if (knownKey.length != 51)
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");

                this._hasCompressedPubKey = false;
                this._networkType = NetworkType.MAIN;
                break;
            }
            case "9" : {
                if (knownKey.length != 51)
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");

                this._hasCompressedPubKey = false;
                this._networkType = NetworkType.TEST;
                break;
            }
            case "L" : case "K" : {
                if (knownKey.length != 52)
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");

                this._networkType = NetworkType.MAIN;
                this._hasCompressedPubKey = true;
                break;
            }
            case "c" : {
                if (knownKey.length != 52)
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");

                this._networkType = NetworkType.TEST;
                this._hasCompressedPubKey = true;
                break;
            }
            default : {
                throw new InvalidNetworkException("Address WIF format must start with either [5] or [9]");
            }

        }


        //strip first byte
        var versionStripped = versionAndDataBytes.sublist(1, versionAndDataBytes.length);

        if (versionStripped.length == 33){
            //drop last byte
            //throw error if last byte is not 0x01 to indicate compression
            if (versionStripped[32] != 0x01)
                throw new InvalidKeyException("Compressed keys must have last byte set as 0x01. Yours is [${versionStripped[32]}]");

            versionStripped = versionStripped.sublist(0, 32);
            this._hasCompressedPubKey = true;
        }else{
            this._hasCompressedPubKey = false;
        }

        var strippedHex = HEX.encode(versionStripped.map((elem) => elem.toUnsigned(8)).toList());

        var d = BigInt.parse(strippedHex, radix: 16);

        this._ecPrivateKey = _privateKeyFromBigInt(d);
        this._d = d;

        this._ecPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    _privateKeyFromBigInt(BigInt d){

        if (d == BigInt.zero)
            throw new BadParameterException('Zero is a bad value for a private key. Pick something else.');

        return new ECPrivateKey(d, _domainParams);
    }

    String toWIF() {
        //convert private key _d to a hex string
        var wifKey = this._d.toRadixString(16);

        if (this._networkType == NetworkType.MAIN)
           wifKey = HEX.encode([0x80]) + wifKey;
        else if (this._networkType == NetworkType.TEST || this._networkType == NetworkType.REGTEST)
            wifKey = HEX.encode([0xef]) + wifKey;

        if (this._hasCompressedPubKey){
            wifKey = wifKey + HEX.encode([0x01]);
        }

        var shaWif = sha256Twice(HEX.decode(wifKey));
        var checksum = shaWif.sublist(0, 4);

        wifKey = wifKey + HEX.encode(checksum);

        var finalWif = bs58check.encode(HEX.decode(wifKey));

        return utf8.decode(finalWif);
    }


    String toHex(){
        return this._d.toRadixString(16);
    }


     Address toAddress({networkType: NetworkType.MAIN}) {

        Address address = this._ecPublicKey.toAddress(this._networkType);
        return address;
    }

    get networkType {
        return this._networkType;
    }


    BigInt get privateKey {
        return this._d;
    }


    SVPublicKey get publicKey  {
        return _ecPublicKey;
    }

    get isCompressed {
        return _hasCompressedPubKey;
    }




}