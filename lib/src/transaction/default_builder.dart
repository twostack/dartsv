
import 'dart:typed_data';

import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';


class DefaultLockBuilder extends LockingScriptBuilder {

  SVScript _script = SVScript();

  DefaultLockBuilder.fromScript(SVScript script): super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
    return _script;
  }

  @override
  void parse(SVScript script) {
    _script = script;
  }

}


class DefaultUnlockBuilder extends UnlockingScriptBuilder{
  SVScript _script = SVScript();

  DefaultUnlockBuilder.fromScript(SVScript script): super.fromScript(script);

  @override
  SVScript getScriptSig() {
    return _script;
  }

  @override
  void parse(SVScript script) {
    _script = script;
  }

  SVScript get scriptSig => _script;
}

