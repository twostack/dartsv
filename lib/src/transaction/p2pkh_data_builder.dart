import 'dart:convert';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/locking_script_builder.dart';
import 'dart:math';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

/**
 * A combination of P2PKH and an "OP_PUSHDATA [data] OP_DROP" pre-prended to the
 * Locking Script. This results in a spendable output that has data attached.
 * The implication here is that spending the output signs over the data.
 *
 * Combined locking + unlocking script has this shape:
 * FIXME: Add in the ScriptSig component. This is just the locking script code
 * 'OP_PUSHDATA1 32 0x2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea OP_DROP OP_DUP OP_HASH160 20 0x581e5e328b0d34d724c09f123c050b341d11d96c OP_EQUALVERIFY OP_CHECKSIG'
 *
 */
class P2PKHDataLockBuilder extends LockingScriptBuilder {
  Address? _address;

  Address? get address => _address;

  List<int>? _pubkeyHash;

  List<int>? get pubkeyHash => _pubkeyHash;

  List<int>? _dataBuffer;

  List<int>? get dataBuffer => _dataBuffer;

  P2PKHDataLockBuilder.fromPublicKey(SVPublicKey pubKey, List<int> data, {NetworkType networkType = NetworkType.MAIN}) {
    _address = Address.fromPublicKey(pubKey, networkType);
    _dataBuffer = data;
  }

  P2PKHDataLockBuilder.fromAddress(Address address, List<int> data) {
    _address = address;
    _dataBuffer = data;

    if (_address != null) {
      _pubkeyHash = HEX.decode(_address!.pubkeyHash160);
    }
  }

  P2PKHDataLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
    if (_pubkeyHash == null || _dataBuffer == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Missing pubkeyHash. Can't construct the script.");
    }

    var builder = ScriptBuilder()
        .addData(Uint8List.fromList(_dataBuffer!))
        .opCode(OpCodes.OP_DROP)
        .opCode(OpCodes.OP_DUP)
        .opCode(OpCodes.OP_HASH160)
        .addData(Uint8List.fromList(_pubkeyHash!))
        .opCode(OpCodes.OP_EQUALVERIFY)
        .opCode(OpCodes.OP_CHECKSIG);

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    if (script != null) {
      var chunkList = script.chunks;

      if (!chunkList[0].isPushData() && chunkList[1].opcodenum != OpCodes.OP_DROP) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Script must start with PUSHDATA & DROP instruction.");
      }

      int chunkListOffset = 0;

      if (chunkList.length == 8) {
        chunkListOffset = 1;
      }

      if (chunkList[chunkListOffset + 4].opcodenum != 20) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Signature and Public Key values are malformed");
      }

      if (!(chunkList[chunkListOffset + 2].opcodenum == OpCodes.OP_DUP &&
          chunkList[chunkListOffset + 3].opcodenum == OpCodes.OP_HASH160 &&
          chunkList[chunkListOffset + 5].opcodenum == OpCodes.OP_EQUALVERIFY &&
          chunkList[chunkListOffset + 6].opcodenum == OpCodes.OP_CHECKSIG)) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Malformed script. Mismatched OP_CODES.");
      }

      _dataBuffer = chunkList[chunkListOffset].buf;
      _pubkeyHash = chunkList[chunkListOffset + 4].buf;
    } else {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,"- Invalid Script or Malformed Script.");
    }
  }
}
