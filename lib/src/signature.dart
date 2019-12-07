import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/privatekey.dart';
import 'package:dartsv/src/publickey.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/export.dart';
import "package:pointycastle/src/utils.dart" as utils;
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:asn1lib/asn1lib.dart';
import 'dart:convert';
import 'dart:math';
import 'package:hex/hex.dart';


class SVSignature {
    final ECDomainParameters _domainParams = new ECDomainParameters('secp256k1');
    static final SHA256Digest _sha256Digest = SHA256Digest();
    final ECDSASigner _dsaSigner = new ECDSASigner(null, HMac(_sha256Digest, 64));
//    final _secureRandom = new FortunaRandom();

    ECSignature _signature;
    BigInt _r;
    BigInt _s;
    String _rHex;
    String _sHex;
    SVPrivateKey _privateKey;
    SVPublicKey _publicKey;

    int _nhashtype = 0;// = SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID; //default to SIGHASH_ALL | SIGHASH_FORKID

    int _i;

    bool _compressed = false;

    SVSignature();

    SVSignature.fromECParams(this._r, this._s) {
        this._signature = ECSignature(r, s);
    }

    SVSignature.fromTxFormat(String buffer) {
        var decoded = HEX.decode(buffer);
        var nhashtype = decoded[decoded.length - 1];

        var derbuf = decoded.sublist(0, decoded.length - 1);
        this._nhashtype = nhashtype; //this is OK. SighashType is already represented as HEX. No decoding needed

        this._parseDER(HEX.encode(derbuf));

//        _secureRandom.seed(KeyParameter(_seed()));
    }


    //fIXME: Initializing from DER won't let you sign / verify
    SVSignature.fromDER(String derBuffer, {sigtype = false}) {
        this._parseDER(derBuffer);
//        _secureRandom.seed(KeyParameter(_seed()));
    }

    void _parseDER(derBuffer) {
        try {
            var parser = new ASN1Parser(HEX.decode(derBuffer));

            ASN1Sequence seq = parser.nextObject() as ASN1Sequence;

            ASN1Integer rVal = seq.elements[0] as ASN1Integer;
            ASN1Integer sVal = seq.elements[1] as ASN1Integer;

            this._rHex = HEX.encode(rVal.valueBytes());
            this._sHex = HEX.encode(sVal.valueBytes());

            this._r = rVal.valueAsBigInteger;
            this._s = sVal.valueAsBigInteger;

            this._signature = ECSignature(r, s);
        } catch (e) {
            throw SignatureException(e.cause);
        }
    }

    /// Initialize from PrivateKey to sign
    SVSignature.fromPrivateKey(SVPrivateKey privateKey) {
        ECPrivateKey privKey = new ECPrivateKey(privateKey.privateKey, this._domainParams);
//        _secureRandom.seed(KeyParameter(_seed()));

        this._privateKey = privateKey;
        this._compressed = privateKey.isCompressed;

        this._dsaSigner.init(true, PrivateKeyParameter(privKey));
    }

    /// Initialize from PublicKey to verify ONLY
    SVSignature.fromPublicKey(SVPublicKey publicKey){
        ECPublicKey pubKey = new ECPublicKey(publicKey.point, this._domainParams);
//        _secureRandom.seed(KeyParameter(_seed()));
        this._dsaSigner.init(false, PublicKeyParameter(pubKey));
    }

    /// Indirect method of initializing from PublicKey for verify ONLY
    /// buffer : Signature in Compact Signature form
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
            throw new SignatureException('i must be 0, 1, 2, or 3');
        }

        if (b2.length != 32){
            throw new SignatureException('r must be 32 bytes');
        }

        if (b3.length != 32){
            throw new SignatureException('s must be 32 bytes');
        }

        this._compressed = compressed;
        this._i = i;
        this._r = utils.decodeBigInt(b2);
        this._s = utils.decodeBigInt(b3);

        this._publicKey = this.recoverPublicKey(i, signedMessage);
        this._dsaSigner.init(false, PublicKeyParameter(new ECPublicKey(this._publicKey.point, _domainParams)));
    }


    List<int> toCompact() {

        if (![0,1,2,3].contains(this._i)) {
            throw new SignatureException('i must be equal to 0, 1, 2, or 3');
        }

        var val = i + 27 + 4;
        if (!this._compressed) {
            val = val - 4;
        }

        var b1 = [val];
        var b2 = utils.encodeBigInt(this._r);
        var b3 = utils.encodeBigInt(this._s);
        return b1 + b2 + b3;
    }


    Uint8List _seed() {
        var random = Random.secure();
        var seed = List<int>.generate(32, (_) => random.nextInt(256));
        return Uint8List.fromList(seed);
    }

    //FIXME: Signature object should be constructed from DER string.
    //       Passing DER sig as a parameter to this class is lame AF.
    bool verify(String message, String derSignature) {
        this._parseDER(derSignature);

        if (this._signature == null)
            throw new SignatureException('Signature is not initialized');

        Uint8List decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

        return this._dsaSigner.verifySignature(decodedMessage, this._signature);
    }

    //Expects a HEX encoded string ! a Better name should be signHex()
    String sign(String message) {
//        this._toLowS(); //force low S before signing: FIXME If shit breaks elsewhere come and have a look here

    //FIXME: Why is the message reversed !? //FIXME: Why is the message reversed !?
        //   Surely this is a protocol-level thing not a signing thing ?
        List<int> decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

        this._signature = this._dsaSigner.generateSignature(decodedMessage);
        this._r = _signature.r;
        this._s = _signature.s;

        this._toLowS();
        return this.toString();
    }

    SVPublicKey recoverPublicKey(int i, List<int> hashBuffer){

        if(![0, 1, 2, 3].contains(i) ){
            throw new SignatureException('i must be equal to 0, 1, 2, or 3');
        }

        var e = utils.decodeBigInt(hashBuffer);
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
        ECPoint nR = R * n;

        if (!nR.isInfinity) {
            throw new SignatureException('nR is not a valid curve point');
        }

        // Compute -e from e
        var eNeg = -e % n;//FIXME: ? unsigned mod ?

        // 1.6.1 Compute Q = r^-1 (sR - eG)
        // Q = r^-1 (sR + -eG)
        var rInv = r.modInverse(n);

        // var Q = R.multiplyTwo(s, G, eNeg).mul(rInv);
        var Q = (R * s + G * eNeg) * rInv;

        ECPublicKey pubkey = ECPublicKey(Q, _domainParams);

        return SVPublicKey.fromXY(Q.x.toBigInteger(), Q.y.toBigInteger(), compressed: this._compressed);
    }


    //FIXME: NOT GENERIC ! I'm conflating concerns of Compact Message Signing with actual
    //       Signature generation here. FIX by factoring out the hashedMessage !
    //       Also, returning SVSignature instance !!??
    SVSignature signWithCalcI(String message){

        //sign it
        List<int> decodedMessage = Uint8List.fromList(HEX.decode(message).toList());

        this._signature = this._dsaSigner.generateSignature(decodedMessage);
        this._r = _signature.r;
        this._s = _signature.s;
        this._toLowS();

        //calculate _i_
        SVPublicKey publicKey = this._privateKey.publicKey;
        for (var i = 0; i < 4; i++) {
            this._i = i;
            SVPublicKey Qprime;
            try {
                Qprime = this.recoverPublicKey(i, decodedMessage);
            } catch (e) {
                continue;
            }

            if (Qprime.point == publicKey.point) {
                this._compressed = Qprime.isCompressed;
                return this;
            }
        }

        this._i = -1;
        throw new SignatureException('Unable to find valid recovery factor');
    }

    @override
    String toString() {
        if (this._signature == null)
            return "";

        return HEX.encode(this.toDER());
    }


    String toTxFormat() {
        //return HEX encoded transaction Format

        var der = this.toDER().toList();

        var buf = Uint8List(1).toList();
        buf[0] = this._nhashtype;

        der.addAll(buf);

        return HEX.encode(der);
    }

    List<int> toDER() {
        ASN1Sequence seq = new ASN1Sequence();
        seq.add(ASN1Integer(this._r));
        seq.add(ASN1Integer(this._s));

        return seq.encodedBytes;
    }

    // [ported from moneybutton/bsv]
    // This function is translated from bitcoind's IsDERSignature and is used in
    // the script interpreter.  This "DER" format actually includes an extra byte,
    // the nhashtype, at the end. It is really the tx format, not DER format.
    //
    // A canonical signature exists of: [30] [total len] [02] [len R] [R] [02] [len S] [S] [hashtype]
    // Where R and S are not negative (their first byte has its highest bit not set), and not
    // excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    // in which case a single 0 byte is necessary and even required).
    //
    // See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623

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


    //
    //  @returns true if the nhashtype is exactly equal to one of the standard options or combinations thereof.
    //  Translated from bitcoind's IsDefinedHashtypeSignature
    //
    bool hasDefinedHashtype() {

        if (!(this._nhashtype != null  && _nhashtype.isFinite && _nhashtype.floor() == _nhashtype && _nhashtype > 0))
            return false;

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


    void _toLowS() {
        if (this._s == null) return;

        // enforce low s
        // see BIP 62, "low S values in signatures"
        if (this._s > BigInt.parse('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', radix: 16)) {
            this._s = this._domainParams.n - this._s;
        }
    }

    //Compares to bitcoind's IsLowDERSignature
    //See also ECDSA signature algorithm which enforces this.
    //See also BIP 62, "low S values in signatures"
    bool hasLowS() {
        var hex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";

        if (this._s < (BigInt.from(1)) || this._s > (BigInt.parse(hex, radix: 16))) {
            return false;
        }
        return
            true;
    }

    BigInt get s => _s;

    BigInt get r => _r;

    SVPublicKey get publicKey => _publicKey;

    void set publicKey(SVPublicKey pubKey) {
       ECPublicKey ecPubKey = new ECPublicKey(pubKey.point, this._domainParams);
//        _secureRandom.seed(KeyParameter(_seed()));
        this._dsaSigner.init(false, PublicKeyParameter(ecPubKey));
    }

    int get i => _i;

    get nhashtype => _nhashtype;

    set nhashtype(value) {
        this._nhashtype = value;
    }

    String get sHex => _sHex;

    String get rHex => _rHex;

}