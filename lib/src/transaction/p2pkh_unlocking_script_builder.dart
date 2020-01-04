import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'package:twostack/src/publickey.dart';
import 'package:twostack/src/script/svscript.dart';
import 'package:twostack/src/signature.dart';
import 'package:twostack/walletsdk.dart';

import 'unlocking_script_builder.dart';

/// The library's default method of creating an "unlocking script" aka a ScriptSig.
///
/// When a user spends a bitcoin, there are two transactions involved; the transaction
/// which currently holds the yet-to-be-spent coins in it's output (UTXO), and the
/// new transaction that be created to "consume" the UTXO in it's entirety.
///
/// The transaction containing the UTXO ([TransactionOutput]) has a script in the output known as a "locking script", or
/// ScriptPubkey. The new transaction to be created must create a corresponding [TransactionInput] ,
/// and in this [TransactionInput] there must be a "unlocking" script which, when
/// combined with the "locking script" creates a valid spending condition as determined by the Script [Interpreter].
///
/// This class generates the default "unlocking script" for a "standard" bitcoin transaction
/// known as P2PKH (Pay-to-Public-Key-Hash).
///
/// See also: [P2PKHLockBuilder]
///
class P2PKHUnlockBuilder extends UnlockingScriptBuilder{

  /// The default implementation for a P2PKH unlocking transaction which
  /// supplies the required Signature and Public Key needed to unlock a
  /// P2PKH UTXO.
  ///
  /// Returns a [SVScript] containing the unlocking script.
  @override
  SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey) {

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var signatureSize = HEX.decode(txSignature.toTxFormat()).length;
    var scriptString =sprintf("%s 0x%s %s 0x%s", [signatureSize, txSignature.toTxFormat(), pubKeySize, signerPubkey.toString()]);

    return SVScript.fromString(scriptString);
  }


}
