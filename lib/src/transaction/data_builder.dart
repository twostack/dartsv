

import 'dart:convert';

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

    if (dataStack == null || dataStack.isEmpty) {
      return SVScript.fromString("OP_FALSE OP_RETURN");
    }

    var scriptPubkey = 'OP_FALSE OP_RETURN';

    var dataScript = SVScript();
    dataScript.add("OP_FALSE");
    dataScript.add("OP_RETURN");
    dataStack.forEach((entry) {

      if (entry != null && HEX.encode(entry).isNotEmpty){

        dataScript.add(entry);
      }

    });
    return dataScript;
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
  List<List<int>> dataStack = [];

  _DataLockBuilder(List<int> dataBuffer){
    dataStack.add(dataBuffer);
  }

  /// Deserializes a Data Output from the provided Script
  ///
  /// The Data Output is expected to have the format :
  ///    `OP_FALSE OP_RETURN <data 1> <data 2> <data n>`
  ///
  @override
  void fromScript(SVScript script) {

    if (script != null
        && script.buffer != null
        && script.chunks.length == 3) {

      var chunks = script.chunks;

      //strip OP_FALSE OP_RETURN and add all data blocks to the stack
      if (chunks[0].opcodenum == OpCodes.OP_FALSE
          && chunks[1].opcodenum == OpCodes.OP_RETURN ) {
          for (var i = 2; i < chunks.length ; i++) {

            if(chunks[i].opcodenum > OpCodes.OP_PUSHDATA4){
              throw ScriptException('Only data pushes allowed. Consider doing ' +
                  'a custom LockBuilder if you have a niche use case for data. ');
            }

            dataStack.add(chunks[i].buf);
          }
      }

    }else{
      throw ScriptException("Invalid Script or Malformed Data Script.");
    }
  }

  void addText(String text){
    dataStack.add(utf8.encode(text));
  }

  void addBuffer(List<int> buffer){
    dataStack.add(buffer);
  }

}

class DataLockBuilder extends _DataLockBuilder with DataLockMixin{
  DataLockBuilder(List<int> data) : super(data);
}

