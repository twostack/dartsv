import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

class P2PKLockBuilder extends LockingScriptBuilder {
  SVPublicKey? signerPubKey;

  P2PKLockBuilder(this.signerPubKey);

  P2PKLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
    if (signerPubKey == null) return SVScript();

    var builder = ScriptBuilder().addData(Uint8List.fromList(HEX.decode(signerPubKey!.toHex()))).opCode(OpCodes.OP_CHECKSIG);

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    if (script == null) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Invalid Script or Malformed Script.");
    }

    if (script != null) {
      List<ScriptChunk> chunkList = script.chunks;

      if (chunkList.length != 2) {
        throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR," - Wrong number of data elements for P2PK Locking Script");
      }

      if (chunkList[1].opcodenum != OpCodes.OP_CHECKSIG) {
        throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, " - Malformed P2PK Locking Script. Mismatched OP_CODES.");
      }
      var pubKeyBuf = chunkList[0].buf;

      if (pubKeyBuf == null) throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Public key value is null");

      signerPubKey = SVPublicKey.fromBuffer(pubKeyBuf);
    }
  }
}

class P2PKUnlockBuilder extends UnlockingScriptBuilder {
  SVPublicKey? signerPubKey;

  P2PKUnlockBuilder(this.signerPubKey);

  P2PKUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptSig() {
    if (!signatures.isEmpty) {
      var signature = signatures[0];

      if (signature == null || signerPubKey == null) {
        return ScriptBuilder().build(); //return empty script; otherwise we will barf on early serialize (prior to signing)
      }

      try {
        var sigBuffer = Uint8List.fromList(HEX.decode(signature.toTxFormat()));
        return ScriptBuilder().addData(sigBuffer).addData(Uint8List.fromList(HEX.decode(signerPubKey!.toHex()))).build();
      } on Exception catch (e) {
        print(e);
      }
    }
    return ScriptBuilder().build();
  }

  @override
  void parse(SVScript script) {
    if (script != null) {
      List<ScriptChunk> chunkList = script.chunks;

      if (chunkList.length != 2) {
        throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, " - Wrong number of data elements for P2PKH ScriptSig");
      }

      var sig = chunkList[0].buf;
      var pubKey = chunkList[1].buf;

      if (sig == null || pubKey == null) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Either one of Signature of Pubkey was not provided (null value)");
      }

      signerPubKey = SVPublicKey.fromBuffer(pubKey);
      signatures.add(SVSignature.fromTxFormat(HEX.encode(sig)));
    } else {
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, " -Invalid Script or Malformed Script.");
    }
  }
}
