

import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/locking_script_builder.dart';
import 'dart:math';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

mixin DataLockMixin on _DataLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){

    if (dataBuffer == null || dataBuffer.length == 0) {
      return SVScript.fromString("OP_FALSE OP_RETURN");
    }

    var opcodenum;
    var len = dataBuffer.length;

    if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
      opcodenum = len;
    } else if (len < pow(2, 8)) {
      opcodenum = OpCodes.OP_PUSHDATA1;
    } else if (len < pow(2, 16)) {
      opcodenum = OpCodes.OP_PUSHDATA2;
    } else if (len < pow(2, 32)) {
      opcodenum = OpCodes.OP_PUSHDATA4;
    } else {
      throw new ScriptException("You can't push that much data");
    }

    var scriptPubkey;
    var encodedData = HEX.encode(dataBuffer);

    if (len < OpCodes.OP_PUSHDATA1)
      scriptPubkey = sprintf('OP_FALSE OP_RETURN %s 0x%s', [len, encodedData]);
    else
      scriptPubkey = sprintf("OP_FALSE OP_RETURN %s %s 0x%s", [opcodenum, len, encodedData]);

    return SVScript.fromString(scriptPubkey);
  }
}

/// Provides locking script (scriptPubkey) functionality for a
/// data output script. Data outputs are represented by a script
/// which makes an Output *permanently* unspendable, and the output script has
/// the following format:
///
///    `OP_FALSE OP_RETURN <pushdata block>`
///
abstract class _DataLockBuilder implements LockingScriptBuilder{
  List<int> dataBuffer;

  _DataLockBuilder(this.dataBuffer);

  /// Deserializes a Data Output from the provided Script
  ///
  /// The Data Output is expected to have the format :
  ///    `OP_FALSE OP_RETURN <pushdata block>`
  ///
  @override
  void fromScript(SVScript script) {

    if (script != null
        && script.buffer != null
        && script.chunks.length == 3) {

      var chunks = script.chunks;

      if (chunks[0].opcodenum == OpCodes.OP_FALSE
          && chunks[1].opcodenum == OpCodes.OP_RETURN ) {
          dataBuffer = chunks[2].buf;
      }

    }else{
      throw ScriptException("Invalid Script or Malformed Data Script.");
    }
  }

}

class DataLockBuilder extends _DataLockBuilder with DataLockMixin{
  DataLockBuilder(List<int> data) : super(data);
}

