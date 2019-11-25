import 'package:dartsv/dartsv.dart';
import 'dart:math';
import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'dart:convert';

class SVPublicKey {
  //We only deal with secp256k1
  final _domainParams = new ECDomainParameters('secp256k1');
  var curve = new ECCurve_secp256k1();

  ECPoint _point;

  ECPublicKey _publicKey;


  SVPublicKey.fromPrivateKey(SVPrivateKey privkey) {

      var decodedPrivKey = encodeBigInt(privkey.privateKey);
      var hexPrivKey = HEX.encode(decodedPrivKey);

      var actualKey = hexPrivKey;
      var point = this._domainParams.G * BigInt.parse(actualKey,radix: 16);
      if (point.x == null && point.y == null)
          throw new InvalidPointException("Can't generate point from private key. Private key greater than N ?");

      //create a new point taking into account compression request/indicator of parent private key
      var finalPoint = _domainParams.curve.createPoint(point.x.toBigInteger(), point.y.toBigInteger(), privkey.isCompressed);

      _checkIfOnCurve(finalPoint); // a bit paranoid

      this._point = finalPoint;
      this._publicKey = ECPublicKey((this._point), _domainParams);
  }


  SVPublicKey.fromX(String xValue, bool oddYValue) {
      this._point = _getPointFromX(xValue, oddYValue);
      this._publicKey = ECPublicKey((this._point), _domainParams);
  }

  ECPoint _getPointFromX(String xValue, bool oddYValue){

      var prefixByte;
      if (oddYValue)
          prefixByte = 0x03;
      else
          prefixByte = 0x02;

      var encoded = HEX.decode(xValue);

      List<int> addressBytes = List<int>(1 + encoded.length);
      addressBytes[0] = prefixByte;
      addressBytes.setRange(1, addressBytes.length, encoded);

      return _decodePoint(HEX.encode(addressBytes));
  }

  SVPublicKey.fromXY(BigInt x, BigInt y, {bool compressed = true}) {

    //create a compressed point by default
    var point = _domainParams.curve.createPoint(x, y, compressed);

    _checkIfOnCurve(point);

    this._point = point;

    this._publicKey = ECPublicKey(this._point, _domainParams);

  }

  static bool isValid(String pubkey) {
      try {
          SVPublicKey.fromHex(pubkey);
      }catch(err){
          return false;
      }

      return true;
  }

  SVPublicKey.fromHex(String str) {
    ECPoint point = _decodePoint(str);

    //see if we can create this point from it's x/y coordinates

    if (point.isInfinity)
        throw new InvalidPointException("That public key generates point at infinity");

    if (point.y.toBigInteger() == BigInt.zero)
        throw new InvalidPointException("Invalid Y value for this public key");

    _checkIfOnCurve(point);


    this._point = point;

    this._publicKey = ECPublicKey(this._point, _domainParams);
  }

  ECPoint _decodePoint(String pkHex) {
    if (pkHex.trim() == '') {
      throw new BadParameterException("Empty compressed public key string");
    }

    var encoded = HEX.decode(pkHex);
    try {
        var point = this._domainParams.curve.decodePoint(encoded);

        if (point.isCompressed && encoded.length != 33)
            throw new BadParameterException(
                "Compressed public keys must be 33 bytes long. Yours is [${encoded
                    .length}]");
        else if (!point.isCompressed && encoded.length != 65)
            throw new BadParameterException(
                "Uncompressed public keys must be 65 bytes long. Yours is [${encoded
                    .length}]");

        _checkIfOnCurve(point);

        return point;

    } on ArgumentError catch(err){
        throw InvalidPointException(err.message) ;
    }
  }

  String _compressPoint(ECPoint point){
        return HEX.encode(point.getEncoded(true));
  }

  _checkIfOnCurve(ECPoint point) {

      //a bit of math copied from PointyCastle. ecc/ecc_fp.dart -> decompressPoint()
      var x = _domainParams.curve.fromBigInteger(point.x.toBigInteger());
      var alpha = (x * ((x * x) + _domainParams.curve.a)) + _domainParams.curve.b;
      ECFieldElement beta = alpha.sqrt();

      if (beta == null)
          throw new InvalidPointException("This point is not on the curve");

      //slight-of-hand. Create compressed point, reconstruct and check Y value.
      var compressedPoint = _compressPoint(point);
      var checkPoint = _domainParams.curve.decodePoint(HEX.decode(compressedPoint));
      if (checkPoint.y.toBigInteger() != point.y.toBigInteger())
          throw new InvalidPointException("This point is not on the curve");

      return (point.x.toBigInteger() == BigInt.zero) && (point.y.toBigInteger() == BigInt.zero);
  }

  String getEncoded(bool compressed) {
    return HEX.encode(this._point.getEncoded(compressed));
  }


  String toString() {
      if (this._point == null)
          return "";

      return HEX.encode(this._point.getEncoded(this._point.isCompressed));
  }

  get point {
      return this._point;
  }

  get isCompressed {
      return this._point.isCompressed;
  }

  Address toAddress(NetworkType nat) {
      //generate compressed addresses by default
      List<int> buffer = this._point.getEncoded(this._point.isCompressed);

      if (this._point.isCompressed) {
          return Address.fromCompressedPubKey(buffer, nat);
      }else{
          return Address.fromHex(HEX.encode(buffer), nat);
      }


  }


  //shelving for now. Might be usefull to have in future
//  get X {
//      var pubx = encodeBigInt(this._point.x.toBigInteger());
//      return HEX.encode(pubx);
//  }
//
//  get Y {
//      var puby = encodeBigInt(this._point.y.toBigInteger());
//      return HEX.encode(puby);
//  }

}
