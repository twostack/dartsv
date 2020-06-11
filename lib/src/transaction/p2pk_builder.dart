
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';

mixin P2PKLockMixin on _P2PKLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){

    if (signerPubkey == null) return SVScript();

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var scriptString = sprintf("%s 0x%s OP_CHECKSIG", [pubKeySize, signerPubkey.toString()]);

    return SVScript.fromString(scriptString);
  }
}

abstract class _P2PKLockBuilder implements LockingScriptBuilder{
  SVPublicKey signerPubkey;

  _P2PKLockBuilder(this.signerPubkey);

  @override
  SVScript get scriptPubkey => getScriptPubkey();

  @override
  void fromScript(SVScript script) {
    throw UnimplementedError();
  }

}

class P2PKLockBuilder extends _P2PKLockBuilder with P2PKLockMixin{
  P2PKLockBuilder(SVPublicKey signerPubkey) : super(signerPubkey);
}


mixin P2PKUnlockMixin on _P2PKUnlockBuilder implements UnlockingScriptBuilder{

  @override
  SVScript getScriptSig() {

    if (signatures.isEmpty) return SVScript();

    var signatureSize = HEX.decode(signatures[0].toTxFormat()).length;
    var scriptString =sprintf("%s 0x%s", [signatureSize, signatures[0].toTxFormat()]);

    return SVScript.fromString(scriptString);
  }

}

abstract class _P2PKUnlockBuilder extends SignedUnlockBuilder implements UnlockingScriptBuilder{

  _P2PKUnlockBuilder();

  @override
  List<SVSignature> signatures = <SVSignature>[];

  @override
  SVScript get scriptSig => getScriptSig();

  @override
  void fromScript(SVScript script) {
    throw UnimplementedError();
  }

}

class P2PKUnlockBuilder extends _P2PKUnlockBuilder with P2PKUnlockMixin{
  P2PKUnlockBuilder() : super();
}

