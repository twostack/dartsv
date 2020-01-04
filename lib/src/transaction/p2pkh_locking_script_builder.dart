import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import 'locking_script_builder.dart';


class P2PKHLockBuilder extends LockingScriptBuilder {
    Address _address;

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

