
import 'dart:typed_data';

import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';

mixin DefaultLockMixin on _DefaultLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){
    return script;
  }
}

abstract class _DefaultLockBuilder implements LockingScriptBuilder{

  SVScript _script = SVScript();
  _DefaultLockBuilder(){
    _script = SVScript.fromBuffer(Uint8List(0));
  }

  @override
  SVScript get scriptPubkey => getScriptPubkey();

  @override
  void fromScript(SVScript script) {
    _script = script;
  }

  SVScript get script => _script;

}

class DefaultLockBuilder extends _DefaultLockBuilder with DefaultLockMixin{
  DefaultLockBuilder() : super();
}


mixin DefaultUnlockMixin on _DefaultUnlockBuilder implements UnlockingScriptBuilder{

  @override
  SVScript getScriptSig() {
    return script;
  }

}

abstract class _DefaultUnlockBuilder extends SignedUnlockBuilder implements UnlockingScriptBuilder{
  SVScript _script = SVScript();

  _DefaultUnlockBuilder();

  @override
  List<SVSignature> signatures = <SVSignature>[];

  @override
  SVScript get scriptSig => getScriptSig();

  @override
  fromScript(SVScript script) {
    _script = script;
  }

  SVScript get script => _script;

}

class DefaultUnlockBuilder extends _DefaultUnlockBuilder with DefaultUnlockMixin{
  DefaultUnlockBuilder() : super();

}

