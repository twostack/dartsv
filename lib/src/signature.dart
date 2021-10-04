import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/privatekey.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import 'exceptions.dart';

/// Sign bitcoin transactions and verify signatures.
///
///
class SVSignature {
    final ECDomainParameters _domainParams =  ECDomainParameters('secp256k1');
    static final SHA256Digest _sha256Digest = SHA256Digest();
    final ECDSASigner _dsaSigner =  ECDSASigner(null, HMac(_sha256Digest, 64));

    ECSignature? _signature;
    BigInt? _r;
    BigInt? _s;
    String? _rHex;
    String? _sHex;
    int _nhashtype = 0;
    int? _i;
    bool _compressed = false;

    SVPrivateKey? _privateKey;
    SVPublicKey? _publicKey;

    /// Construct a  instance from the R and S components of an ECDSA signature.
    ///
    /// [r] - The r component of the signature
    ///
    /// [s] - The s component of the signature
    SVSignature.fromECParams(this._r, this._s) {
        _signature = ECSignature(_r!, _s!);
    }

    /// Constructs a signature for it's bitcoin-transaction-encoded form.
    ///
    /// [buffer] - A hexadecimal string containing the signature from a bitcoin transaction.
    SVSignature.fromTxFormat(String buffer) {
        //FIXME: Add guards to assert TxFormat
        var decoded = HEX.decode(buffer);
        var nhashtype = decoded[decoded.length - 1];

        var derbuf = decoded.sublist(0, decoded.length - 1);
        _nhashtype = nhashtype; //this is OK. SighashType is already represented as HEX. No decoding needed

        _parseDER(HEX.encode(derbuf));

    }


    /// Constructs a signature from it's DER-encoded form
    ///
    /// [derBuffer] - Hex-encoded DER string containing the signature
    SVSignature.fromDER(String derBuffer, {SVPublicKey? publicKey = null}) {
        _publicKey = publicKey;
        _parseDER(derBuffer);
    }


    /// Construct a signature instance from a PrivateKey for signing purposes.
    SVSignature.fromPrivateKey(SVPrivateKey privateKey) {
        ECPrivateKey privKey =  ECPrivateKey(privateKey.privateKey, _domainParams);

        _privateKey = privateKey;
        _compressed = privateKey.isCompressed;

        _dsaSigner.init(true, PrivateKeyParameter(privKey));
    }

    /// Constructs a signature instance from PublicKey for verification *ONLY*.
    SVSignature.fromPublicKey(SVPublicKey publicKey){
        ECPublicKey pubKey =  ECPublicKey(publicKey.point, _domainParams);
        _publicKey = publicKey;
        _dsaSigner.init(false, PublicKeyParameter(pubKey));
    }

    /// Construct the Signature and recover the public key.
    /// With the public key recovered we can use this signature for *verification only*
    ///
    /// This paper (secion 4.1.6) describes an algorithm for recovering the public key from an ECDSA signature:
    /// (http://www.secg.org/sec1-v2.pdf)
    ///
    /// [buffer] - Signature in Compact Signature form
    ///
    /// [signedMessage] - Message signed with the signature in [buffer]
    ///
    SVSignature.fromCompact(List<int> buffer, List<int> signedMessage){

        var compressed = true;
        var i = buffer.sublist(0, 1)[0] - 27 - 4;
        if (i < 0) {
            compressed = false;
            i = i + 4;
        }

        var b2 = buffer.sublist(1, 33);
        var b3 = buffer.sublist(33, 65);

        if (![0 ,1 , 2, 3].contains(i)){
            throw  SignatureException('i must be 0, 1, 2, or 3');
        }

        if (b2.length != 32){
            throw  SignatureException('r must be 32 bytes');
        }

        if (b3.length != 32){
            throw  SignatureException('s must be 32 bytes');
        }

        _compressed = compressed;
        _i = i;

        var tmp = HEX.encode(b2);
        _r = BigInt.parse(tmp, radix: 16);
        tmp = HEX.encode(b3);
        _s = BigInt.parse(tmp, radix: 16);

        _rHex = _r!.toRadixString(16);
        _sHex = _s!.toRadixString(16);

        _signature = ECSignature(_r!, _s!);

        _publicKey = _recoverPublicKey(i, signedMessage);
        _dsaSigner.init(false, PublicKeyParameter( ECPublicKey(_publicKey!.point, _domainParams)));
    }


    /// Renders the signature in *compact* form.
    ///
    /// Returns a buffer containing the ECDSA signature in compact format allowing for
    /// public key recovery. See the [fromCompact()] constructor
    List<int> toCompact() {

        if (![0,1,2,3].contains(_i)) {
            throw  SignatureException('i must be equal to 0, 1, 2, or 3');
        }

        var val = _i! + 27 + 4;
        if (!_compressed) {
            val = val - 4;
        }

        var b1 = [val];

        //This is a hack around the problem of having r-values or s-values of length 31. This causes invalid sigs
        //see: https://github.com/twostack/dartsv/issues/35
        var b2Padded= sprintf("%064s", [_r!.toRadixString(16)]).replaceAll(' ', '0');
        var b2 = HEX.decode(b2Padded);
        var b3Padded= sprintf("%064s", [_s!.toRadixString(16)]).replaceAll(' ', '0');
        var b3 = HEX.decode(b3Padded);
        return b1 + b2 + b3;
    }


    /// Verify that the provided message was signed using this signature
    ///
    /// [message] - The message to verify as a hexadecimal string
    bool verify(String message) {
//expecting a String here is confusing. Make it a List<int> so the caller
//can be forced to do hex encoding via HEX.encode(utf8.encode())
        if (_signature == null) {
            throw SignatureException('Signature is not initialized');
        }

        var decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

        return _dsaSigner.verifySignature(decodedMessage, _signature!);
    }


    /// Signs a message and optionally also calculates the first byte needed for compact format rendering.
    ///
    /// *NOTE:* - subsequent
    ///
    /// [message] - The message to sign
    ///
    /// [forCompact] - If *true* then we perform additional calculation of first byte needed to render the signature in compact format with [toCompact()]
    String sign(String message, {bool forCompact = false}){

        if (_privateKey == null){
            throw SignatureException('Missing private key. Initialise this signature instance using fromPrivateKey()');
        }


        //sign it
        List<int> decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

        _signature = _dsaSigner.generateSignature(decodedMessage as Uint8List) as ECSignature;
        _r = _signature!.r;
        _s = _signature!.s;
        _rHex = _r!.toRadixString(16);
        _sHex = _s!.toRadixString(16);

        _toLowS();

        //calculate _i_
        if (forCompact) {
            _calculateI(decodedMessage);
        }

        return toString();
    }


    @override
    String toString() {
        if (_signature == null) {
            return '';
        }

        return HEX.encode(toDER());
    }


    /// Returns the signature in standard DER format, with the [SighashType] value appended
    String toTxFormat() {
        //return HEX encoded transaction Format

        var der = toDER().toList();

        var buf = Uint8List(1).toList();
        buf[0] = _nhashtype;

        der.addAll(buf);

        return HEX.encode(der);
    }

    /// Renders the signature as a DER-encoded byte buffer
    List<int> toDER() {
        var seq =  ASN1Sequence();
        seq.add(ASN1Integer(_r));
        seq.add(ASN1Integer(_s));

        return seq.encode();
    }

    /// [ported from moneybutton/bsv]
    /// This function is translated from bitcoind's IsDERSignature and is used in
    /// the script interpreter.  This 'DER' format actually includes an extra byte,
    /// the nhashtype, at the end. It is really the tx format, not DER format.
    ///
    /// ```
    /// A canonical signature exists of: [30] [total len] [02] [len R] [R] [02] [len S] [S] [hashtype]
    /// Where R and S are not negative (their first byte has its highest bit not set), and not
    /// excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    /// in which case a single 0 byte is necessary and even required).
    ///
    /// See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    /// ```
    static bool isTxDER(String buffer) {
        List<int> buf;
        try {
            buf = HEX.decode(buffer);
        } catch (ex) {
            return false;
        }

        if (buf.length < 9) {
            //  Non-canonical signature: too short
            return false;
        }
        if (buf.length > 73) {
            // Non-canonical signature: too long
            return false;
        }
        if (buf[0] != 0x30) {
            //  Non-canonical signature: wrong type
            return false;
        }
        if (buf[1] != buf.length - 3) {
            //  Non-canonical signature: wrong length marker
            return false;
        }
        var nLenR = buf[3];
        if (5 + nLenR >= buf.length) {
            //  Non-canonical signature: S length misplaced
            return false;
        }
        var nLenS = buf[5 + nLenR];
        if ((nLenR + nLenS + 7) != buf.length) {
            //  Non-canonical signature: R+S length mismatch
            return false;
        }

        var R = buf.sublist(4, buf.length);
        if (buf[4 - 2] != 0x02) {
            //  Non-canonical signature: R value type mismatch
            return false;
        }
        if (nLenR == 0) {
            //  Non-canonical signature: R length is zero
            return false;
        }
        if (R[0] & 0x80 != 0) {
            //  Non-canonical signature: R value negative
            return false;
        }
        if (nLenR > 1 && (R[0] == 0x00) && !(R[1] & 0x80 != 0)) {
            //  Non-canonical signature: R value excessively padded
            return false;
        }

        var S = buf.sublist(6 + nLenR, buf.length);
        if (buf[6 + nLenR - 2] != 0x02) {
            //  Non-canonical signature: S value type mismatch
            return false;
        }
        if (nLenS == 0) {
            //  Non-canonical signature: S length is zero
            return false;
        }
        if (S[0] & 0x80 != 0) {
            //  Non-canonical signature: S value negative
            return false;
        }
        if (nLenS > 1 && (S[0] == 0x00) && !(S[1] & 0x80 != 0)) {
            //  Non-canonical signature: S value excessively padded
            return false;
        }
        return true;
    }


    ///
    ///  Returns true if the hashType is exactly equal to one of the standard options or combinations thereof.
    ///  Translated from bitcoind's IsDefinedHashtypeSignature
    ///
    bool hasDefinedHashtype() {

        if (!(_nhashtype != null  && _nhashtype.isFinite && _nhashtype.floor() == _nhashtype && _nhashtype > 0)) {
            return false;
        }

        // accept with or without Signature.SIGHASH_ANYONECANPAY by ignoring the bit
        try {
            var temp = _nhashtype & 0x1F;
            if (temp < SighashType.SIGHASH_ALL || temp > SighashType.SIGHASH_SINGLE) {
                return false;
            }
        } catch (ex) {
            return false;
        }
        return true;
    }

    ///Comparable to bitcoind's IsLowDERSignature. Returns true if the signature has a 'low' S-value.
    ///
    ///See also ECDSA signature algorithm which enforces
    ///See also BIP 62, 'low S values in signatures'
    bool hasLowS() {
        var hex = '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';

        if (_s! < (BigInt.from(1)) || _s! > (BigInt.parse(hex, radix: 16))) {
            return false;
        }

        return true;
    }


    // side-effects on _i
    void _calculateI(List<int> decodedMessage){

        var pubKey = _privateKey!.publicKey;
        for (var i = 0; i < 4; i++) {
            _i = i;
            SVPublicKey Qprime;
            try {
                Qprime = _recoverPublicKey(i, decodedMessage);
            } catch (e) {
                continue;
            }

            if (Qprime.point == pubKey.point) {
                _compressed = Qprime.isCompressed;
                return;
            }
        }

        _i = -1;
        throw  SignatureException('Unable to find valid recovery factor');
    }


    SVPublicKey _recoverPublicKey(int i, List<int> hashBuffer){

        if(![0, 1, 2, 3].contains(i) ){
            throw  SignatureException('i must be equal to 0, 1, 2, or 3');
        }

        var tmp = HEX.encode(hashBuffer);
        var e = BigInt.parse(tmp, radix: 16);

        var r = this.r;
        var s = this.s;

        // The more significant bit specifies whether we should use the
        // first or second candidate key.
        var isSecondKey = i >> 1 != 0;

        BigInt n = _domainParams.n;
        ECPoint G = _domainParams.G;

        // 1.1 Let x = r + jn
        BigInt x = isSecondKey ? r + n : r;
        var yTilde = i & 1;
        ECPoint R = _domainParams.curve.decompressPoint(yTilde, x);

        // 1.4 Check that nR is at infinity
        ECPoint? nR = R * n;

        if (!nR!.isInfinity) {
            throw  SignatureException('nR is not a valid curve point');
        }

        // Compute -e from e
        var eNeg = -e % n;//FIXME: ? unsigned mod ?

        // 1.6.1 Compute Q = r^-1 (sR - eG)
        // Q = r^-1 (sR + -eG)
        var rInv = r.modInverse(n);

        // var Q = R.multiplyTwo(s, G, eNeg).mul(rInv);
        var Q = (((R * s)! + G * eNeg)! * rInv)!;

        return SVPublicKey.fromXY(Q.x!.toBigInteger()!, Q.y!.toBigInteger()!, compressed: _compressed);
    }




    void _toLowS() {
        if (_s == null) return;

        // enforce low s
        // see BIP 62, 'low S values in signatures'
        if (_s! > BigInt.parse('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', radix: 16)) {
            _s = _domainParams.n - _s!;
        }
    }


    void _parseDER(derBuffer) {
        try {
            var parser =  ASN1Parser(HEX.decode(derBuffer) as Uint8List);

            var seq = parser.nextObject() as ASN1Sequence;

            var rVal = seq.elements![0] as ASN1Integer;
            var sVal = seq.elements![1] as ASN1Integer;

            _rHex = HEX.encode(rVal.valueBytes!);
            _sHex = HEX.encode(sVal!.valueBytes!);

            _r = BigInt.parse(_rHex!, radix: 16);
            _s = BigInt.parse(_sHex!, radix: 16);

            _signature = ECSignature(r, s);
        } catch (err) {
            throw err;
        }
    }


    /// Returns the signature's *S* value
    BigInt get s => _s!;

    /// Returns the signature's *R* value
    BigInt get r => _r!;

    /// Returns the public key that will be used to verify signatures
    SVPublicKey get publicKey => _publicKey!;

//    int get i => _i;

    /// Returns the [SighashType] value that was detected with [fromTxFormat()] constructor
    int get nhashtype => _nhashtype;

    /// Force a specific [SighashType] value that will be returned with [toTxFormat()]
    set nhashtype(value) {
        _nhashtype = value;
    }

    /// Returns the signature's *S* value as a hexadecimal string
    String get sHex => _sHex!;

    /// Returns the signature's *R* value as a hexadecimal string
    String get rHex => _rHex!;

}