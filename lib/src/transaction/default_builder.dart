
import 'package:dartsv/src/script/svscript.dart';

import 'locking_script_builder.dart';
import 'unlocking_script_builder.dart';


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

