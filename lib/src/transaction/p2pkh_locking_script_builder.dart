import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'package:twostack/src/encoding/utils.dart';
import 'package:twostack/walletsdk.dart';

import 'locking_script_builder.dart';

/// Default implementation that generates P2PKH (Pay-To-Public-Key-Hash)
/// output scripts.
///
/// In every transaction that you create on the bitcoin ledger, you will
/// have one or more output transactions. These output transactions will
/// either generate a "change" output (sending remaining coins back to the sender)
/// or will "send coins" to another recipient.
///
/// When "sending coins" to another recipient, what actually happens is that
/// an output script is created on the blockchain which "locks" the funds in
/// such a way that they can only be "unlocked" by the recipient. This script
/// is essentially a puzzle to which only the recipient knows the answer.
///
/// In a P2PKH script the way that funds are locked is with a hash digest of the
/// recipient's Public Key and a requirement for the recipient to produce a signature
/// using the Public Key's matching Private Key.
///
/// You can implement a custom [LockingScriptBuilder] to construct "non-standard"
/// ways of "locking" coins.
class P2PKHLockBuilder extends LockingScriptBuilder {
    Address _address;

    /// Construct a new
    P2PKHLockBuilder(this._address);

    @override
    SVScript getScriptPubkey(){
        var destAddress = _address.address;

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

