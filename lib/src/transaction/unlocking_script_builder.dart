
import 'package:twostack/src/publickey.dart';
import 'package:twostack/src/script/svscript.dart';
import 'package:twostack/src/signature.dart';

abstract class UnlockingScriptBuilder {
    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey);
}

