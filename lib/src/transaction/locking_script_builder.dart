
import 'package:dartsv/dartsv.dart';

/// Base class for the Locking Script part of the Script Builder API
///
abstract class LockingScriptBuilder {

    SVScript? script;

    ///This method must be implemented by all subclasses. It must return a
    ///valid locking script a.k.a scriptPubkey
    SVScript getScriptPubkey();

    void parse(SVScript script);

    //construct from script
    LockingScriptBuilder.fromScript(SVScript script){
        this.script = script;
        this.parse(script);
    }

    //default constructor
    LockingScriptBuilder(){
       this.script = ScriptBuilder().build();
    }
}
