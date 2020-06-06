


import 'package:dartsv/src/transaction/GScriptBuilder.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';

mixin P2PKLockMixin on _P2PKLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){

    if (signerPubkey == null) return SVScript();

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var scriptString = sprintf("%s 0x%s", [pubKeySize, signerPubkey.toString()]);

    return SVScript.fromString(scriptString);
  }
}

abstract class _P2PKLockBuilder implements LockingScriptBuilder{
  SVPublicKey signerPubkey;

  _P2PKLockBuilder(this.signerPubkey);

  @override
  SVScript get scriptPubkey => getScriptPubkey();

}

class P2PKLockBuilder extends _P2PKLockBuilder with P2PKLockMixin{
  P2PKLockBuilder(SVPublicKey signerPubkey) : super(signerPubkey);
}


mixin P2PKUnlockMixin on _P2PKUnlockBuilder implements UnlockingScriptBuilder{

  @override
  SVScript getScriptSig() {

    if (signature == null) return SVScript();

    var signatureSize = HEX.decode(signature.toTxFormat()).length;
    var scriptString =sprintf("%s 0x%s", [signatureSize, signature.toTxFormat()]);

    return SVScript.fromString(scriptString);
  }

}

abstract class _P2PKUnlockBuilder extends SignedUnlockBuilder implements UnlockingScriptBuilder{
  SVSignature signature;

  _P2PKUnlockBuilder();

  @override
  SVScript get scriptSig => getScriptSig();

}

class P2PKUnlockBuilder extends _P2PKUnlockBuilder with P2PKUnlockMixin{
  P2PKUnlockBuilder() : super();
}

