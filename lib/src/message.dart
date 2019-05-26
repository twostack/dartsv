import 'package:dartsv/dartsv.dart';

//FIXME: I don't see the point of this class right now. Seems redundant
class Message {
    String _message;

    Message(String message) {
        this._message = message;
    }

    String sign(SVPrivateKey privateKey) {
        var signature = SVSignature.fromPrivateKey(privateKey);
        return signature.sign(this._message);
    }

    String get message => _message;

    bool verifyFromAddress(Address address, String signature) {
        return true;
    }

    bool verifyFromPublicKey(SVPublicKey publicKey, String sigStr){

        SVSignature signature = SVSignature.fromPublicKey(publicKey);
        return signature.verify(this._message, "");

    }

}