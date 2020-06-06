

import 'package:dartsv/dartsv.dart';

abstract class GScriptBuilder implements LockingScriptBuilder, UnlockingScriptBuilder{

  LockingScriptBuilder _locker;
  UnlockingScriptBuilder _unlocker;

  GScriptBuilder(this._locker, this._unlocker);

  SVScript get scriptSig => _unlocker.getScriptSig();

  SVScript get scriptPubkey => _locker.getScriptPubkey();

}

