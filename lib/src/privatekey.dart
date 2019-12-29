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

/// Manages an ECDSA private key.
///
/// Bitcoin uses ECDSA for it's public/private key cryptography.
/// Specifically it uses the `secp256k1` elliptic curve.
///
/// This class wraps cryptographic operations related to ECDSA from the
/// [PointyCastle](https://pub.dev/packages/pointycastle) library/package.
///
/// You can read a good primer on Elliptic Curve Cryptography at [This Cloudflare blog post](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/)
///
///
class SVPrivateKey {

    final _domainParams = new ECDomainParameters('secp256k1');
    final _secureRandom = new FortunaRandom();

    var _hasCompressedPubKey = false;
    var _networkType = NetworkType.MAIN; //Mainnet by default

    var random = new Random.secure();

    BigInt _d;
    ECPrivateKey _ecPrivateKey;
    SVPublicKey _svPublicKey;

    /// Constructs a new random private key.
    ///
    /// [networkType] - Optional network type. Defaults to mainnet. The network type is only
    /// used when serialising the Private Key in *WIF* format. See [toWIF()].
    ///
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
        this._svPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    /// Constructs a new Private Key from a Big Integer.
    ///
    /// [privateKey] - The private key as a Big Integer value. Remember that in
    /// ECDSA we compute the public key (Q) as `Q = d * G`
    SVPrivateKey.fromBigInt(BigInt privateKey){
        this._ecPrivateKey = _privateKeyFromBigInt(privateKey);
        this._d = privateKey;
        this._hasCompressedPubKey = true;
        this._svPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    /// Construct a new Private Key from the hexadecimal value representing the
    /// BigInt value of (d) in ` Q = d * G `
    ///
    /// [privhex] - The BigInt representation of the private key as a hexadecimal string
    ///
    /// [networkType] - The network type we intend to use to corresponding WIF representation on.
    SVPrivateKey.fromHex(String privhex, NetworkType networkType) {
        var d = BigInt.parse(privhex,radix: 16);

        this._hasCompressedPubKey = true;
        this._networkType = networkType;
        this._ecPrivateKey = _privateKeyFromBigInt(d);
        this._d = d;
        this._svPublicKey = SVPublicKey.fromPrivateKey(this);
    }

    /// Construct a new Private Key from the WIF encoded format.
    ///
    /// WIF is an abbreviation for Wallet Import Format. It is a format based on base58-encoding
    /// a private key so as to make it resistant to accidental user error in copying it. A wallet
    /// should be able to verify that the WIF format represents a valid private key.
    ///
    /// [wifKey] - The private key in WIF-encoded format. See [this bitcoin wiki entry](https://en.bitcoin.it/wiki/Wallet_import_format)
    ///
    SVPrivateKey.fromWIF(String wifKey){

        if (wifKey.length != 51 && wifKey.length != 52){
            throw new InvalidKeyException("Valid keys are either 51 or 52 bytes in length");
        }

       //decode from base58
        List<int> versionAndDataBytes = bs58check.decodeChecked(wifKey);


        switch (wifKey[0]){
            case "5" : {
                if (wifKey.length != 51)
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");

                this._hasCompressedPubKey = false;
                this._networkType = NetworkType.MAIN;
                break;
            }
            case "9" : {
                if (wifKey.length != 51)
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");

                this._hasCompressedPubKey = false;
                this._networkType = NetworkType.TEST;
                break;
            }
            case "L" : case "K" : {
                if (wifKey.length != 52)
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");

                this._networkType = NetworkType.MAIN;
                this._hasCompressedPubKey = true;
                break;
            }
            case "c" : {
                if (wifKey.length != 52)
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

        this._svPublicKey = SVPublicKey.fromPrivateKey(this);
    }



    /// Returns this Private Key in WIF format. See [toWIF()].
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


    /// Returns the *naked* private key Big Integer value as a hexadecimal string
    String toHex(){
        return this._d.toRadixString(16);
    }

    //convenience method to retrieve an address
    /// Convenience method that jumps through the hoops of generating and [Address] from this
    /// Private Key's corresponding [SVPublicKey].
    Address toAddress({networkType: NetworkType.MAIN}) {
        //FIXME: set network type to default parameter unless explicitly specified ?
        Address address = this._svPublicKey.toAddress(this._networkType);
        return address;
    }

    Uint8List _seed() {
        var random = Random.secure();
        var seed = List<int>.generate(32, (_) => random.nextInt(256));
        return Uint8List.fromList(seed);
    }

    _privateKeyFromBigInt(BigInt d){

        if (d == BigInt.zero)
            throw new BadParameterException('Zero is a bad value for a private key. Pick something else.');

        return new ECPrivateKey(d, _domainParams);
    }


    /// Returns the Network Type that we intend to use this private key on.
    /// This is also the value encoded in the WIF format representation of this key.
    get networkType {
        return this._networkType;
    }


    /// Returns the *naked* private key Big Integer value as a Big Integer
    BigInt get privateKey {
        return this._d;
    }


    /// Returns the [SVPublicKey] corresponding to this ECDSA private key.
    ///
    /// NOTE: `Q = d * G` where *Q* is the public key, *d* is the private key and `G` is the curve's Generator.
    SVPublicKey get publicKey  {
        return _svPublicKey;
    }

    /// Returns true if the corresponding public key for this private key
    /// is in *compressed* format. To read more about compressed public keys see [SVPublicKey().getEncoded()]
    get isCompressed {
        return _hasCompressedPubKey;
    }




}