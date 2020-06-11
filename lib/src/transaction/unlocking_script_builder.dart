
import 'package:dartsv/src/publickey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/signature.dart';

abstract class UnlockingScriptBuilder {
    ///This method must be implemented by all subclasses. It must return a
    ///valid unlocking script a.k.a scriptSig
    SVScript getScriptSig();

    ///This method must be implemented by all subclasses.
    ///
    ///The implementation of this method should be able to parse the script,
    ///and recover the internal state of the subclass. I.e. it must deserialize
    ///the unlocking script.
    ///
    void fromScript(SVScript script);
}

