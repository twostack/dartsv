import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'package:twostack/src/publickey.dart';
import 'package:twostack/src/script/svscript.dart';
import 'package:twostack/src/signature.dart';

import 'unlocking_script_builder.dart';

class P2PKHUnlockBuilder extends UnlockingScriptBuilder{

  @override
  SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey) {

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var signatureSize = HEX.decode(txSignature.toTxFormat()).length;
    var scriptString =sprintf("%s 0x%s %s 0x%s", [signatureSize, txSignature.toTxFormat(), pubKeySize, signerPubkey.toString()]);

    return SVScript.fromString(scriptString);
  }


}
