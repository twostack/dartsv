

import 'package:dartsv/src/script/svscript.dart';

/// Base class for the Locking Script part of the Script Builder API
///
abstract class LockingScriptBuilder {
    ///This method must be implemented by all subclasses. It must return a
    ///valid locking script a.k.a scriptPubkey
    SVScript getScriptPubkey();

    ///This method must be implemented by all subclasses.
    ///
    ///The implementation of this method should be able to parse the script,
    ///and recover the internal state of the subclass. I.e. it must deserialize
    ///the locking script.
    ///
    void fromScript(SVScript script);
}
