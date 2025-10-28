

import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

class HodlUnlockBuilder extends UnlockingScriptBuilder{

  SVSignature _spendingSig;
  SVPublicKey _pubKey;
  List<int> _txPreimage;

  HodlUnlockBuilder(this._spendingSig, this._pubKey, this._txPreimage);

  @override
  SVScript getScriptSig() {

    return ScriptBuilder()
        .addData(Uint8List.fromList(hex.decode(_spendingSig.toTxFormat())))
        .addData(Uint8List.fromList(hex.decode(_pubKey.toHex())))
        .addData(Uint8List.fromList(_txPreimage))
        .build();
  }

  @override
  void parse(SVScript script) {
    throw UnimplementedError();
  }

}