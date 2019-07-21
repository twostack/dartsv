import 'dart:convert';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/impl.dart';

/*
Bitcoin Signed Messages
 */
class Message {
    List<int> _message;
    SVPrivateKey _privateKey;


    final MAGIC_BYTES = 'Bitcoin Signed Message:\n';

    List<int> magicHash() {

        var prefix1 = MAGIC_BYTES.length;
        var prefix2 = this._message.length;
        var buf = HEX.encode([prefix1] + utf8.encode(MAGIC_BYTES) + [prefix2] + this._message);
        var hash = sha256Twice(HEX.decode(buf));
        return hash;
    }

    Message(List<int> message) {
        this._message = message;
    }

    String sign(SVPrivateKey privateKey) {
        var signature = SVSignature.fromPrivateKey(privateKey);
        this._privateKey = privateKey;
        signature = signature.signWithCalcI(HEX.encode(this.magicHash()));

        List<int> compactSig = signature.toCompact();

        return base64Encode(compactSig);
    }

    List<int> get message => _message;

    // sigBuffer - Base64-encoded Compact Signature
    bool verifyFromAddress(Address address, String sigBuffer) {
        SVSignature signature = SVSignature.fromCompact(base64Decode(sigBuffer), this.magicHash());

        SVPublicKey recoveredPubKey = signature.publicKey;

        Address recoveredAddress = recoveredPubKey.toAddress(address.networkType);

        //sanity check on address
        //FIXME : Why is toString() on "same" address returning different values
        ///       AND why is toBase58() == toString() !!!???
        if (address.toBase58() != recoveredAddress.toBase58()) {
            return false;
        }

        return this._verify(signature);
    }

    //sigBuffer - Base64-encoded Compact Signature
    bool verifyFromPublicKey(SVPublicKey publicKey, String sigBuffer) {

        SVSignature signature = SVSignature.fromCompact(base64Decode(sigBuffer), this.magicHash());

        SVPublicKey recoveredKey = signature.publicKey;

        //sanity check on public key
        if (recoveredKey.point != publicKey.point) {
            return false;
        }

        return this._verify(signature);

    }

    bool _verify(SVSignature signature) {
        var hash = this.magicHash();

        ///FIXME: So much hoop-jumping ! I already have a Signature instance, why am I passing another signature into it's "verify" method !!???
        ///
        return signature.verify(HEX.encode(hash), HEX.encode(signature.toDER()));
    }

}