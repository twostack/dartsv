
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';


/// ** P2PMS (multisig) locking Script (output script / scriptPubkey) ***
mixin P2SHLockMixin on _P2SHLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){
   // OP_HASH160 <the script hash> OP_EQUAL
    if (scriptHash == null || scriptHash.isEmpty) return SVScript();

    var hashHex = HEX.decode(scriptHash);
    var script = sprintf('OP_HASH160 %s 0x%s OP_EQUAL', [hashHex.length, scriptHash]);

    return SVScript.fromString(script);
  }

}

abstract class _P2SHLockBuilder implements LockingScriptBuilder {

  String scriptHash;

  _P2SHLockBuilder(this.scriptHash);

  /// In this case our fromScript() method won't assume that we are being passed
  /// a P2SH formatted script. I.e. the usual format of `OP_HASH160 <hash> OP_EQUAL`
  /// won't be assumed.
  ///
  /// [script] - Arbitrary script for which we want to generate a P2SH locking script
  @override
  void fromScript(SVScript script) {

    if (script != null && script.buffer != null) {
      //create a hash of the serialized script
      var hash = hash160(HEX.decode(script.toHex()));

      scriptHash = HEX.encode(hash);

    }else{
      throw ScriptException("Invalid Script or Malformed Script.");
    }

  }
}

class P2SHLockBuilder extends _P2SHLockBuilder with P2SHLockMixin {
  P2SHLockBuilder(String hash) : super(hash);
}


/// P2SH unlocking Script
mixin P2SHUnlockMixin on _P2SHUnlockBuilder implements UnlockingScriptBuilder{

  @override
  SVScript getScriptSig() {
    return script!;
  }

}

/// Signatures are injected by the framework when you call Transaction().signInput()
/// Make consecutive calls to the signInput() function to had the signatures
/// added to the [SignedUnlockBuilder] instance associated with the [Transaction].
///
abstract class _P2SHUnlockBuilder extends SignedUnlockBuilder implements UnlockingScriptBuilder {

  @override
  List<SVSignature> signatures = <SVSignature>[];

  SVScript? script;

  _P2SHUnlockBuilder();

  @override
  void fromScript(SVScript script) {
    if (script != null && script.buffer != null) {
      this.script = script;
    }else{
      throw ScriptException("Invalid Script or Malformed Script.");
    }
  }

  SVScript get scriptSig => getScriptSig();
}

class P2SHUnlockBuilder extends _P2SHUnlockBuilder with P2SHUnlockMixin{

  P2SHUnlockBuilder() : super();

}





