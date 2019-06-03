import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'dart:math';

import 'package:dartsv/src/encoding/base58check.dart';

import '../address.dart';
import '../exceptions.dart';
import 'opcodes.dart';

class ScriptChunk {

    List<int> _buf;
    int _len;
    int _opcodenum;

    ScriptChunk(this._buf, this._len, this._opcodenum);

    int get opcodenum => _opcodenum;

    set opcodenum(int value) {
        _opcodenum = value;
    }

    int get len => _len;

    set len(int value) {
        _len = value;
    }

    List<int> get buf => _buf;

    set buf(List<int> value) {
        _buf = value;
    }


}

mixin ScriptBuilder {
    String buildScript();
}

class SVScript with ScriptBuilder {

    String _script = "";

    List<ScriptChunk> _chunks = List();

//    bool _isDataOutFlag = false;

    Uint8List _byteArray = Uint8List(0);

//    var _isPubkeyHash = false;

    //FIXME: I'm not convinced this does what I think it does. Recheck !
    SVScript.fromString(String script){
//        this._script = script;
//        parse(script);
        this._processChunks(script);
    }

    SVScript.fromHex(String script){
        this._script = script;
        parse(script);

    }

    SVScript.fromChunks(List<ScriptChunk> chunks) {
        this._chunks = chunks;
    }

    SVScript.fromByteArray(Uint8List buffer) {
        this._byteArray = buffer;
    }


    SVScript() {
        this._processChunks(buildScript());
    }

    //expect "script" param to be human-readable encoding of opcodes
//    SVScript(String script) {
//        this._script = script;
//        parse(script);
//    }


    _processChunks(String script) {
        if (script.trim().isEmpty) {
            return;
        }

        var tokenList = script.split(" "); //split on spaces

        //encode tokens, leaving non-token elements intact
        for (var index = 0; index < tokenList.length;) {
            var token = tokenList[index];
            var opcode = token;
            var opcodenum = OpCodes.opcodeMap[token];

            if (opcodenum == null) {
                opcodenum = int.parse(token);
                if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
                    _chunks.add(ScriptChunk(HEX.decode(tokenList[index + 1].substring(2)), opcodenum, opcodenum));
                    index = index + 2; //step by two
                } else {
                    throw new ScriptException('Invalid script: ' + script);
                }
            } else if (opcodenum == OpCodes.OP_PUSHDATA1 ||
                opcodenum == OpCodes.OP_PUSHDATA2 ||
                opcodenum == OpCodes.OP_PUSHDATA4) {
                if (tokenList[index + 2].substring(0, 2) != '0x') {
                    throw new ScriptException('Pushdata data must start with 0x');
                }
                _chunks.add(ScriptChunk(HEX.decode(tokenList[index + 2].substring(2)), int.parse(tokenList[index + 1], radix: 16), opcodenum));
                index = index + 3; //step by three
            } else {
                chunks.add(ScriptChunk([], 0, opcodenum));
                index = index + 1; //step by one
            }
        }

        this._script = script;
        parse(script);
    }


//    /// standard pubkeyScript for P2PKH
//    /// FIXME: this constructor name bothers me
//    SVScript.buildPublicKeyHashOut(Address fromAddress) {
//        var addressLength = HEX
//            .decode(fromAddress.address)
//            .length;
//
//        var destAddress = fromAddress.address;
//        //FIXME: Another hack. For some reason some addresses don't have proper ripemd160 hashes of the hex value. Fix later !
//        if (addressLength == 33) {
//            addressLength = 20;
//            destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
//        }
//        this._script = sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);
//        parse(this._script);
//    }

//    /// standard sigScript for P2PKH
//    /// FIXME: this constructor name bothers me.
//    SVScript.buildScriptSig(String signature, String pubKey){
//        var pubKeySize = HEX
//            .decode(pubKey)
//            .length;
//        var signatureSize = HEX
//            .decode(signature)
//            .length;
//        this._script = sprintf("%s 0x%s %s 0x%s", [signatureSize, signature, pubKeySize, pubKey]);
//        parse(this._script);
//    }


//    SVScript.buildDataOut(String data) {
//        var opcodenum;
//        var len = utf8
//            .encode(data)
//            .length;
//        var encodedData = HEX.encode(utf8.encode(data));
//
//        if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
//            opcodenum = len;
//        } else if (len < pow(2, 8)) {
//            opcodenum = OpCodes.OP_PUSHDATA1;
//        } else if (len < pow(2, 16)) {
//            opcodenum = OpCodes.OP_PUSHDATA2;
//        } else if (len < pow(2, 32)) {
//            opcodenum = OpCodes.OP_PUSHDATA4;
//        } else {
//            throw new ScriptException("You can't push that much data");
//        }
//
//        if (len < OpCodes.OP_PUSHDATA1)
//            this._script = sprintf("%s %s", [len, encodedData]);
//        else
//            this._script = sprintf("%s %s %s", [opcodenum, len, encodedData]);
//
//        this._isDataOutFlag = true;
//
//        parse(this._script);
//    }


//    SVScript.empty(){
//        this._script = "";
//    }

    Uint8List get buffer {
        return this._byteArray;
    }

//    bool get isPubkeyHash => this._isPubkeyHash;

    String toString() {
        if (_chunks.isNotEmpty) {
            return _chunks.fold("", (String prev, ScriptChunk chunk) => prev + _chunkToString(chunk)).trim();
        }

        return this._script;
    }

    String get script {
        return _script;
    }

    void parse(String script) {
        if (script == null || script.isEmpty) return;

        var tokenList = script.split(" "); //split on spaces

        //encode tokens, leaving non-token elements intact
        var encodedList = tokenList.map((token) {
            var encodedToken = token;
            if (OpCodes.opcodeMap[token.trim()] == null) { //if the token is not in the opCodeMap, it's data

                if (token.indexOf("0x") >= 0 || tokenList.length == 1) { //it's either a 0x-prefixed bit of data, or a hex string
                    encodedToken = token.replaceAll("0x", ""); //strip hex coding identifier if any
                } else {
                    try { //try to parse value as int

                        var tokenVal = int.parse(encodedToken); //FIXME: Dear lord have mercy

                        if (tokenVal >= 1 && tokenVal <= 75) { //if true => this is number-of-following-bytes-to-push
                            encodedToken = tokenVal.toRadixString(16);
                        }
                    } catch (ex) {}
                }
            } else {
                encodedToken = OpCodes.opcodeMap[token.trim()].toRadixString(16);
            }
            return encodedToken;
        });

//        this._isPubkeyHash = checkPubkeyHash(encodedList.toList());

        //remove spaces. conc
        String hex = encodedList.fold("", (prev, elem) => prev + elem);

        this._byteArray = HEX.decode(hex);
    }

    //serialize the script to HEX
    String toHex() {
        return HEX.encode(this._byteArray);
    }

//    bool isDataOut() => this._isDataOutFlag;


    bool isPushOnly() {
        return _chunks.fold(true, (prev, chunk) {
            return prev && (chunk.opcodenum <= OpCodes.OP_16 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA1 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA2 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA4);
        });
    }

    bool isScriptHashOut() {
        return false;
    }

    List<ScriptChunk> get chunks => _chunks;

    bool checkMinimalPush(int i) {
        return false;
    }

    void findAndDelete(SVScript tmpScript) {

    }

    String _chunkToString(ScriptChunk chunk, {type = 'hex'}) {
        var opcodenum = chunk.opcodenum;
        var asm = (type == 'asm');
        var str = '';
        if (chunk.buf.isEmpty) {
            // no data chunk
            if (OpCodes.opcodeMap.containsValue(opcodenum)) {
                if (asm) {
                    /*
        // A few cases where the opcode name differs from reverseMap
        // aside from 1 to 16 data pushes.
        if (opcodenum == 0) {
          // OP_0 -> 0
          str = str + ' 0'
        } else if (opcodenum === 79) {
          // OP_1NEGATE -> 1
          str = str + ' -1'
        } else {
          str = str + ' ' + Opcode(opcodenum).toString()
        }
           */
                } else {
                    str = str + ' ' + OpCodes.fromNum(opcodenum);
                }
            } else {
                var numstr = opcodenum.toRadixString(16);
                if (numstr.length % 2 != 0) {
                    numstr = '0' + numstr;
                }
                if (asm) {
                    str = str + ' ' + numstr;
                } else {
                    str = str + ' ' + '0x' + numstr;
                }
            }
        } else {
            // data chunk
            if (!asm && (opcodenum == OpCodes.OP_PUSHDATA1 ||
                opcodenum == OpCodes.OP_PUSHDATA2 ||
                opcodenum == OpCodes.OP_PUSHDATA4)) {
                str = str + ' ' + OpCodes.fromNum(opcodenum);
            }
            if (chunk.len > 0) {
                if (asm) {
                    str = str + ' ' + HEX.encode(chunk.buf);
                } else {
                    str = str + ' ' + chunk.len.toString() + ' ' + '0x' + HEX.encode(chunk.buf);
                }
            }
        }
        return str;
    }

    @override
    String buildScript() {
        // TODO: implement buildScript
        return null;
    }
}

