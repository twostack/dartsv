
import 'package:dartsv/src/script/svscript.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

class P2PKHScriptSig extends SVScript with ScriptSig{

  String _signature;
  String _pubKey;

  P2PKHScriptSig.fromByteArray(List<int> buffer) : super.fromByteArray(buffer);

  P2PKHScriptSig.fromString(String script) : super.fromString(script);

//  P2PKHScriptSig.fromHex(String hex) : super.fromHex(hex);

  P2PKHScriptSig(this._signature, this._pubKey);

  /// standard sigScript for P2PKH
  String buildScript(){
    var pubKeySize = HEX.decode(_pubKey).length;
    var signatureSize = HEX.decode(_signature).length;
    return sprintf("%s 0x%s %s 0x%s", [signatureSize, _signature, pubKeySize, _pubKey]);
  }

  String get signature => _signature;


}