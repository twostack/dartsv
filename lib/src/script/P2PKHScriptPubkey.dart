

import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../address.dart';

class P2PKHScriptPubkey extends SVScript with ScriptPubkey{
  Address _fromAddress;

  P2PKHScriptPubkey(this._fromAddress);

  //FIXME: Investigate this method of constructor inheritance. Feels wonky.
  P2PKHScriptPubkey.fromByteArray(List<int> buffer) : super.fromByteArray(buffer);
  P2PKHScriptPubkey.fromString(String string) : super.fromString(string);

  /// standard pubkeyScript for P2PKH
  String buildScript() {
    var addressLength = HEX.decode(this._fromAddress.address).length;

    var destAddress = this._fromAddress.address;
    //FIXME: Another hack. For some reason some addresses don't have proper ripemd160 hashes of the hex value. Fix later !
    if (addressLength == 33) {
      addressLength = 20;
      destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
    }
    return sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);
//    this._script = sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);
//    parse(this._script);
  }


  ///FIXME: This should not be part of SVScript, but a specialization of a PKH Template Script
  ///       Transaction instances will then have to be injected with the specialized Script Template
  ///       which in turn is constructed by a factory method somewhere
  bool checkPubkeyHash(List<String> tokenList) {
    try {
      if (tokenList.length == 4) {
        var signatureBuf = HEX.decode(tokenList[1]);
        var pubkeyBuf = HEX.decode(tokenList[3]);
        if (signatureBuf[0] == 0x30) {
          var version = pubkeyBuf[0];
          if ((version == 0x04 || version == 0x06 || version == 0x07) && pubkeyBuf.length == 65) {
            return true;
          } else if ((version == 0x03 || version == 0x02) && pubkeyBuf.length == 33) {
            return true;
          }
        }
      }

      return false;
    } catch (ex) {
      print(ex);
      return false;
    }
  }


//  get isPubkeyHash => checkPubkeyHash(this.script);

}