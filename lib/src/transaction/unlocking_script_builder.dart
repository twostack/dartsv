
import 'package:dartsv/dartsv.dart';

abstract class UnlockingScriptBuilder {

    List<SVSignature> _signatures = List.empty(growable: true);

    List<SVSignature> get signatures => List.unmodifiable(_signatures);

    SVScript? script;

    ///This method must be implemented by all subclasses. It must return a
    ///valid unlocking script a.k.a scriptSig
    SVScript getScriptSig();

    void parse(SVScript script);

    UnlockingScriptBuilder.fromScript(SVScript script){
        this.script = script;
        this.parse(script);
    }

    UnlockingScriptBuilder(){
        this.script = ScriptBuilder().build();
    }

    void addSignature(SVSignature signature){
        this._signatures.add(signature);
    }
}

