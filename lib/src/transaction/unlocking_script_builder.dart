
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/signature.dart';

abstract class UnlockingScriptBuilder {
    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey);
}

