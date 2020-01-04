

import 'package:twostack/walletsdk.dart';

/// An interface that specifies the contract for creating
/// custom "locking scripts" aka ScripPubkeys.
///
/// NOTE: Please proceed with extreme caution when using this feature.
/// If not used with care this can result in permanently locking up
/// funds. Remember to test your code on the Testnet first.
///
/// *NOTE:* If you implement a custom LockingScriptBuilder you will possibly need
/// an equivalent [UnlockingScriptBuilder] because chances are that no other wallet
/// will be able to spend or detect UTXOs/transactions you create with a custom locking script.
///
/// Example showing the library's default P2PKH Lock Builder:
/// ```
///
/// class P2PKHLockBuilder extends LockingScriptBuilder {
///     Address _address;
///
///     P2PKHLockBuilder(this._address);
///
///     @override
///     SVScript getScriptPubkey(){
///         var destAddress = _address.address;
///
///         var addressLength = HEX.decode(destAddress).length;
///
///         if (addressLength == 33) {
///             addressLength = 20;
///             destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
///         }
///         var scriptString = sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);
///
///         return SVScript.fromString(scriptString);
///     }
/// }

/// ```
///
/// Example of how to override the Locking Script Builder:
///
/// ```
/// var transaction = new Transaction()
///     .spendFromMap(simpleUtxoWith1BSV)
///     .spendTo(toAddress, BigInt.from(546))
///     .withLockingScriptBuilder(P2PKHLockBuilder(toAddress))
///     .sendChangeTo(changeAddress);
/// transaction.signInput( 0, privateKey);
/// ```
///
abstract class LockingScriptBuilder {

    /// Returns your custom locking script as an instance of [SVScript]
    SVScript getScriptPubkey();
}
