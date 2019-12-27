import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import 'encoding/utils.dart';
import 'exceptions.dart';

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
        var point = this._domainParams.G * BigInt.parse(actualKey, radix: 16);
        if (point.x == null && point.y == null)
            throw new InvalidPointException("Can't generate point from private key. Private key greater than N ?");

        //create a new point taking into account compression request/indicator of parent private key
        var finalPoint = _domainParams.curve.createPoint(point.x.toBigInteger(), point.y.toBigInteger(), privkey.isCompressed);

        _checkIfOnCurve(finalPoint); // a bit paranoid

        this._point = finalPoint;
        this._publicKey = ECPublicKey((this._point), _domainParams);
    }


    SVPublicKey.fromX(String xValue, bool oddYValue, {bool strict = false}) {
        this._point = _getPointFromX(xValue, oddYValue);
        this._publicKey = ECPublicKey((this._point), _domainParams);
    }


    SVPublicKey.fromXY(BigInt x, BigInt y, {bool compressed = true, bool strict = false}) {
        //create a compressed point by default
        var point = _domainParams.curve.createPoint(x, y, compressed);

        _checkIfOnCurve(point);

        this._point = point;

        this._publicKey = ECPublicKey(this._point, _domainParams);
    }

    SVPublicKey.fromDER(List<int> buffer, {bool strict = true}){

        if (buffer.isEmpty) {
            throw new BadParameterException("Empty compressed DER buffer");
        }

        this._point = _transformDER(buffer, strict);

        if (this._point.isInfinity)
            throw new InvalidPointException("That public key generates point at infinity");

        if (this._point.y.toBigInteger() == BigInt.zero)
            throw new InvalidPointException("Invalid Y value for this public key");

        _checkIfOnCurve(this._point);

        this._publicKey = ECPublicKey(this._point, _domainParams);
    }


    SVPublicKey.fromHex(String pubkey, {bool strict = true}) {

        if (pubkey.trim() == '') {
            throw new BadParameterException("Empty compressed public key string");
        }

//        _parseHexString(pubkey);
        this._point = _transformDER(HEX.decode(pubkey), strict);

        if (this._point.isInfinity)
            throw new InvalidPointException("That public key generates point at infinity");

        if (this._point.y.toBigInteger() == BigInt.zero)
            throw new InvalidPointException("Invalid Y value for this public key");

        _checkIfOnCurve(this._point);

        this._publicKey = ECPublicKey(this._point, _domainParams);
    }


    ECPoint _transformDER(List<int> buf, bool strict) {
        BigInt x;
        BigInt y;
        List<int> xbuf;
        List<int> ybuf;
        ECPoint point;

        if (buf[0] == 0x04 || (!strict && (buf[0] == 0x06 || buf[0] == 0x07))) {
            xbuf = buf.sublist(1, 33);
            ybuf = buf.sublist(33, 65);
            if (xbuf.length != 32 || ybuf.length != 32 || buf.length != 65) {
                throw new InvalidPointException('Length of x and y must be 32 bytes');
            }
            x = BigInt.parse(HEX.encode(xbuf), radix: 16);
            y = BigInt.parse(HEX.encode(ybuf), radix: 16);

            point = _domainParams.curve.createPoint(x, y);
        } else if (buf[0] == 0x03 || buf[0] == 0x02) {
            xbuf = buf.sublist(1);
            x = BigInt.parse(HEX.encode(xbuf), radix: 16);

            int yTilde = buf[0] & 1;
            point = _domainParams.curve.decompressPoint(yTilde, x);
        } else {
            throw InvalidPointException('Invalid DER format public key');
        }
        return point;
    }

    _parseHexString(String pubkey) {

        ECPoint point = _decodePoint(pubkey);

        //see if we can create this point from it's x/y coordinates


        if (point.isInfinity)
            throw new InvalidPointException("That public key generates point at infinity");

        if (point.y.toBigInteger() == BigInt.zero)
            throw new InvalidPointException("Invalid Y value for this public key");

        _checkIfOnCurve(point);


        this._point = point;

        this._publicKey = ECPublicKey(this._point, _domainParams);
    }


    ECPoint _getPointFromX(String xValue, bool oddYValue) {
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

    static bool isValid(String pubkey) {
        SVPublicKey publicKey;
        try {
            publicKey = SVPublicKey.fromHex(pubkey);
        } catch (err) {
            return false;
        }

        return true;
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
        } on ArgumentError catch (err) {
            throw InvalidPointException(err.message);
        }
    }

    String _compressPoint(ECPoint point) {
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

    ECPoint get point {
        return this._point;
    }

    bool get isCompressed {
        return this._point.isCompressed;
    }

    Address toAddress(NetworkType nat) {
        //generate compressed addresses by default
        List<int> buffer = this._point.getEncoded(this._point.isCompressed);

        if (this._point.isCompressed) {
            return Address.fromCompressedPubKey(buffer, nat);
        } else {
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
