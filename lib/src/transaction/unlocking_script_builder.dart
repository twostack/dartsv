
import 'package:twostack/src/publickey.dart';
import 'package:twostack/src/script/svscript.dart';
import 'package:twostack/src/signature.dart';
import 'package:twostack/src/transaction/locking_script_builder.dart';

/// An interface that specifies the contract for creating a custom "unlocking script" aka a ScriptSig
///
/// When one creates a custom "locking script" using the [LockingScriptBuilder] interface,
/// it is important that there be a corresponding "unlocking" implementation that allows one to
/// spend the coins (in the likely event that you ever want to see your money again).
///
/// *Example implementation showing the default P2PKH [UnlockingScriptBuilder]:*
/// ```
/// class P2PKHUnlockBuilder extends UnlockingScriptBuilder{
///
///     @override
///     SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey) {
///
///         var pubKeySize = HEX.decode(signerPubkey.toString()).length;
///         var signatureSize = HEX.decode(txSignature.toTxFormat()).length;
///         var scriptString =sprintf("%s 0x%s %s 0x%s", [signatureSize, txSignature.toTxFormat(), pubKeySize, signerPubkey.toString()]);
///
///         return SVScript.fromString(scriptString);
///     }
/// }
/// ```
///
/// *Example showing how to use a custom UnlockingScriptBuilder* :
/// ```
/// var transaction = new Transaction()
///     .spendFromMap(simpleUtxoWith1BSV)
///     .spendTo(toAddress, BigInt.from(546))
///     .withUnLockingScriptBuilder(P2PKHUnlockBuilder())
///     .sendChangeTo(changeAddress);
/// transaction.signInput( 0, privateKey);
/// ```
abstract class UnlockingScriptBuilder {
    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey);
}

