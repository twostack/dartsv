
import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';



class P2MSLockBuilder extends LockingScriptBuilder{

  List<SVPublicKey> publicKeys = List.empty();
  int requiredSigs = 0;
  bool sorting = false;

  P2MSLockBuilder(this.publicKeys, this.requiredSigs, {this.sorting = true});

  P2MSLockBuilder.fromScript(SVScript script): super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
    if (publicKeys.isEmpty || requiredSigs == 0) return SVScript();

    if (publicKeys.length > 15){
      throw ScriptException("Too many public keys. P2MS limit is 15 public keys");
    }

    if (requiredSigs! > publicKeys.length) {
      throw ScriptException("You can't have more signatures than public keys");
    }

    if (sorting) {
      publicKeys.sort((a, b) => a.toString().compareTo(b.toString())); //sort the keys by default
    }
    var pubKeyString = publicKeys.fold('', (dynamic prev, elem) => prev + sprintf(' %s 0x%s', [HEX.decode(elem.toHex()).length, elem.toHex()]));

    var scriptString = sprintf('OP_%s %s OP_%s OP_CHECKMULTISIG', [requiredSigs, pubKeyString, publicKeys.length]);

    //OP_3 <pubKey1> <pubKey2> <pubKey3> <pubKey4> <pubKey5> OP_5 OP_CHECKMULTISIG
    return SVScript.fromString(scriptString);
  }

  @override
  void parse(SVScript script) {

    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList[chunkList.length - 1].opcodenum != OpCodes.OP_CHECKMULTISIG){
        throw ScriptException("Malformed multisig script. OP_CHECKMULTISIG is missing.");
      }

      var keyCount = chunkList[0].opcodenum - 80;

      publicKeys = <SVPublicKey>[];
      for (var i = 1; i < keyCount + 1; i++){
        publicKeys.add(SVPublicKey.fromDER(chunkList[i].buf));
      }

      requiredSigs = chunkList[keyCount + 1].opcodenum - 80;

    }else{
      throw ScriptException("Invalid Script or Malformed Script.");
    }
  }

}


class P2MSUnlockBuilder extends UnlockingScriptBuilder {

  P2MSUnlockBuilder();

  P2MSUnlockBuilder.fromSignatures(List<SVSignature> signatures) {
      this.signatures.addAll(signatures);
  }

  P2MSUnlockBuilder.fromScript(SVScript script): super.fromScript(script);

  @override
  SVScript getScriptSig() {

    var multiSigs = signatures.fold('', (dynamic prev, elem) => prev + sprintf(' %s 0x%s', [HEX.decode(elem.toTxFormat()).length, elem.toTxFormat()]));

    return SVScript.fromString('OP_0 ${multiSigs}');
  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      //skip first chunk. typically OP_O
      for (var i = 1; i < chunkList.length; i++){
        signatures.add(SVSignature.fromTxFormat(HEX.encode(chunkList[i].buf)));
      }

    }else{
      throw ScriptException("Invalid Script or Malformed Script.");
    }
  }

  SVScript get scriptSig => getScriptSig();

}





