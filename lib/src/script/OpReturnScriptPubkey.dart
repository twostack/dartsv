import 'dart:convert';
import 'dart:math';

import 'package:dartsv/src/script/svscript.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../exceptions.dart';
import 'opcodes.dart';

class OpReturnScriptPubkey extends SVScript {

    String _data;

    OpReturnScriptPubkey(this._data);

    String buildScript() {
        var opcodenum;
        var len = utf8.encode(_data).length;
        var encodedData = HEX.encode(utf8.encode(_data));

        if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
            opcodenum = len;
        } else if (len < pow(2, 8)) {
            opcodenum = OpCodes.OP_PUSHDATA1;
        } else if (len < pow(2, 16)) {
            opcodenum = OpCodes.OP_PUSHDATA2;
        } else if (len < pow(2, 32)) {
            opcodenum = OpCodes.OP_PUSHDATA4;
        } else {
            throw new ScriptException("You can't push that much data");
        }

        if (len < OpCodes.OP_PUSHDATA1)
            return sprintf("%s %s", [len, encodedData]);
        else
            return sprintf("%s %s %s", [opcodenum, len, encodedData]);

//        this._isDataOutFlag = true;

//        parse(this._script);
    }
}