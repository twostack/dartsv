import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';

/**
 * A locking script that starts with "OP_FALSE OP_RETURN" which renders the output
 * unspendable. Allows for data to be appended to the script.
 *
 * WARNING: Importantly you should ensure that you have zero satoshis in the output of this
 *       script. Any satoshis attached to this output will be UNSPENDABLE
 * Locking script format will be e.g.
 * 'OP_FALSE OP_RETURN OP_PUSHDATA1 32 0x2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea'
 *
 */
class UnspendableDataLockBuilder extends LockingScriptBuilder {
  List<int>? _dataBuffer;
  List<int>? get dataBuffer => _dataBuffer;

  UnspendableDataLockBuilder(List<int> data){
    this._dataBuffer = List.unmodifiable(data);
  }

  UnspendableDataLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {


    var builder = ScriptBuilder()
        .opCode(OpCodes.OP_FALSE)
        .opCode(OpCodes.OP_RETURN);

    if(_dataBuffer != null && _dataBuffer!.length != 0)
      builder.addData(Uint8List.fromList(_dataBuffer!));

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    if (script != null) {
      var chunkList = script.chunks;

      if (chunkList.length < 2) throw ScriptException("Script must start with OP_FALSE OP_RETURN instructions"); //no need to proceed

      if (!chunkList[0].equalsOpCode(OpCodes.OP_FALSE) && chunkList[1].equalsOpCode(OpCodes.OP_RETURN)) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR.mnemonic + " - Script must start with OP_FALSE OP_RETURN instructions.");
      }

      if (chunkList[2].isPushData()){
        _dataBuffer = chunkList[2].buf;
      }

    } else {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR.mnemonic + "- Invalid Script or Malformed Script.");
    }
  }
}
