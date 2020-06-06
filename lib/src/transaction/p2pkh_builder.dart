

import 'package:dartsv/src/transaction/GScriptBuilder.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';


/// ** P2PKH locking Script ***
mixin P2PKHLockMixin on _P2PKHLockBuilder implements LockingScriptBuilder {

  @override
  SVScript getScriptPubkey(){

    if (address == null) return SVScript();

    var destAddress = address.address;

    var addressLength = HEX.decode(destAddress).length;

    //FIXME: Another hack. For some reason some addresses don't have proper ripemd160 hashes of the hex value. Fix later !
    if (addressLength == 33) {
      addressLength = 20;
      destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
    }
    var scriptString = sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);

    return SVScript.fromString(scriptString);
  }
}

abstract class _P2PKHLockBuilder implements LockingScriptBuilder {
  Address address;
  _P2PKHLockBuilder(this.address);
}

class P2PKHLockBuilder extends _P2PKHLockBuilder with P2PKHLockMixin {
  P2PKHLockBuilder(Address address) : super(address);
}


/// ** P2PKH unlocking Script (scriptSig / Input script) ***
mixin P2PKHUnlockMixin on _P2PKHUnlockBuilder implements UnlockingScriptBuilder{

  @override
  SVScript getScriptSig() {

    if (signature == null || signerPubkey == null) return SVScript();

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var signatureSize = HEX.decode(signature.toTxFormat()).length;
    var scriptString =sprintf("%s 0x%s %s 0x%s", [signatureSize, signature.toTxFormat(), pubKeySize, signerPubkey.toString()]);

    return SVScript.fromString(scriptString);
  }

}

abstract class _P2PKHUnlockBuilder extends SignedUnlockBuilder implements UnlockingScriptBuilder {
  SVPublicKey signerPubkey;

  @override
  SVSignature signature;

  //The signature *must* be injected later, because of the way SIGHASH works
  _P2PKHUnlockBuilder(this.signerPubkey);

  SVScript get scriptSig => getScriptSig();


}

class P2PKHUnlockBuilder extends _P2PKHUnlockBuilder with P2PKHUnlockMixin{

  //Expect the Signature to be injected after the fact. Input Signing is a
  //weird one.
  P2PKHUnlockBuilder(SVPublicKey signerPubkey) : super(signerPubkey);



}




