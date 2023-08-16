
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';

/// ** P2PKH locking Script ***
class P2PKHLockBuilder extends LockingScriptBuilder {

  Address? address;
  List<int>? pubkeyHash;

  P2PKHLockBuilder.fromAddress(Address address){
    this.address = address;
    pubkeyHash = HEX.decode(address.pubkeyHash160);
  }

  P2PKHLockBuilder.fromPublicKey(SVPublicKey publicKey, {NetworkType networkType = NetworkType.MAIN}){
    this.address = publicKey.toAddress(networkType);
    pubkeyHash = HEX.decode(address!.pubkeyHash160);
  }

  P2PKHLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {

    if (this.pubkeyHash == null){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,"Missing pubkey hash value");
    }

    var builder = ScriptBuilder()
      .opCode(OpCodes.OP_DUP)
      .opCode(OpCodes.OP_HASH160)
      .addData(Uint8List.fromList(pubkeyHash!))
      .opCode(OpCodes.OP_EQUALVERIFY)
      .opCode(OpCodes.OP_CHECKSIG);

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 5) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptPubkey");
      }

      if (chunkList[2].len != 20) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Signature and Public Key values are malformed");
      }

      if (!(chunkList[0].opcodenum == OpCodes.OP_DUP &&
          chunkList[1].opcodenum == OpCodes.OP_HASH160 &&
          chunkList[3].opcodenum == OpCodes.OP_EQUALVERIFY &&
          chunkList[4].opcodenum == OpCodes.OP_CHECKSIG)) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Malformed P2PKH ScriptPubkey script. Mismatched OP_CODES.");
      }

      pubkeyHash = chunkList[2].buf;
    }
  }

}

class P2PKHUnlockBuilder extends UnlockingScriptBuilder {

  SVPublicKey? signerPubkey;

  P2PKHUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  P2PKHUnlockBuilder(this.signerPubkey);

  @override
  SVScript getScriptSig() {
    if (signatures == null || signatures.isEmpty || signerPubkey == null) return SVScript();

    var signature = signatures[0];
    var sigBuffer = Uint8List.fromList(HEX.decode(signature.toTxFormat()));
    var pkBuffer = Uint8List.fromList(HEX.decode(signerPubkey!.toHex()));

    return ScriptBuilder()
        .addData(sigBuffer)
        .addData(pkBuffer)
        .build();
  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 2) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptSig");
      }

      var sig = chunkList[0].buf;
      var pubKey = chunkList[1].buf;

      if (sig == null || pubKey == null){
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Either one of Signature of Pubkey was not provided (null value)");
      }

      signerPubkey = SVPublicKey.fromHex(HEX.encode(pubKey));
      signatures.add(SVSignature.fromTxFormat(HEX.encode(sig)));
    } else {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
    }
  }

  SVScript get scriptSig => getScriptSig();
}






