
import 'dart:typed_data';

import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/script_error.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/script_builder.dart';
import 'package:hex/hex.dart';

import 'locking_script_builder.dart';
import 'unlocking_script_builder.dart';



class P2SHLockBuilder extends LockingScriptBuilder {

  String? scriptHash;

  P2SHLockBuilder(this.scriptHash);

  P2SHLockBuilder.fromScript(SVScript script): super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
   // OP_HASH160 <the script hash> OP_EQUAL
    if (scriptHash == null || scriptHash!.isEmpty) return SVScript();

    var hashHex = HEX.decode(scriptHash!);
    var builder = ScriptBuilder()
      .opCode(OpCodes.OP_HASH160)
      .addData(Uint8List.fromList(hashHex))
      .opCode(OpCodes.OP_EQUAL);

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      //create a hash of the serialized script
      var hash = hash160(HEX.decode(script.toHex()));

      scriptHash = HEX.encode(hash);

    }else{
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
    }
  }

}

class P2SHUnlockBuilder extends UnlockingScriptBuilder{

  SVScript? script;

  P2SHUnlockBuilder(this.script);

  P2SHUnlockBuilder.fromString(SVScript script): super.fromScript(script);

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      this.script = script;
    }else{
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
    }
  }

  @override
  SVScript getScriptSig() {
    return script ??= SVScript();
  }

  SVScript get scriptSig => getScriptSig();

}







