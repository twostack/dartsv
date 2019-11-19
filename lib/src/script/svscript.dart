import 'dart:collection';
import 'dart:convert';
import 'dart:ffi';
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

mixin ScriptSig{
}

mixin ScriptPubkey {
}

mixin ScriptBuilder {
    String buildScript();
}


//FIXME: Move internal script representation to be consistently that of List<ScriptChunk>
class SVScript with ScriptBuilder {

    String _script = "";

    List<ScriptChunk> _chunks = [];

//    bool _isDataOutFlag = false;

    Uint8List _byteArray = Uint8List(0);

//    var _isPubkeyHash = false;

//    SVScript.parse(String script){
//        this._script = script;
//        parse(script);
//    }

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

    _convertChunksToByteArray(){
        String chunkString = this._chunks.fold("", (prev, elem) => prev + _chunkToString(elem, type: 'asm'));
        this._byteArray = Uint8List.fromList(HEX.decode(chunkString.replaceAll(' ', '')));
    }

    SVScript.fromChunks(List<ScriptChunk> chunks) {
        this._chunks = chunks;
        _convertChunksToByteArray();
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


    SVScript.fromBitcoindString(String str) {
        List<int> bw = [];
        var tokens = str.split(' ');
        for (var i = 0; i < tokens.length; i++) {
            var token = tokens[i];
            if (token == '') {
                continue;
            }

            var opstr;
            int opcodenum;
            var tbuf;
            if (token.startsWith("0x")) {
                var hex = token.substring(2);
                bw.addAll(HEX.decode(hex));
                opcodenum = int.parse(token);
            } else if (token[0] == '\'') {
                String tstr = token.substring(1, token.length - 1);
                tbuf = SVScript().add(tstr).buffer;
                bw.addAll(tbuf);
            } else if (OpCodes.opcodeMap.containsKey("OP_${token}")) {
                opstr = 'OP_' + token;
                opcodenum = OpCodes.opcodeMap[opstr];
                bw.add(opcodenum);
            } else if (OpCodes.opcodeMap[token] is num) {
                opstr = token;
                opcodenum = OpCodes.opcodeMap[opstr];
                bw.add(opcodenum);
            } else if (int.tryParse(token) != null) {
                var script = SVScript()
                    ..add(BigInt.tryParse(token));
                tbuf = script.buffer;
                bw.add(tbuf);
            } else {
                throw new ScriptException('Could not determine type of script value');
            }
        }
        Uint8List buffer = Uint8List.fromList(bw);

        _processBuffer(buffer);
    }


    SVScript.fromBuffer(Uint8List buffer) {
        _processBuffer(buffer);
    }

    _processBuffer(Uint8List buffer){

        Uint8List br = Uint8List.fromList(buffer);
        int pos = 0;
        for( int entry in br) {
            var opcodenum = entry;
            pos = pos + 1;
            int len;
            Uint8List buf;
            if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
                len = opcodenum;
                _chunks.add(ScriptChunk(
                    br.sublist(pos, len + 1),
                    len,
                    opcodenum
                ));
                pos = pos + len + 1;
                if (pos + len >= br.length) {
                    break;
                }
            } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
                len = entry;
                buf = br.sublist(0, len);
                pos = pos + len;
                _chunks.add(ScriptChunk(
                    buf,
                    len,
                    opcodenum
                ));
                if (pos + len >= br.length) {
                    break;
                }
            } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
                len = int.parse(HEX.encode(br.sublist(0, 2)), radix: 16); //read size of data (2 bytes)
                buf = br.sublist(pos, len); //read the amount of data specified by "len"
                pos = pos + len;

                //Construct a scriptChunk
                _chunks.add(ScriptChunk(
                    buf,
                    len,
                    opcodenum
                ));

                if (pos + len >= br.length) {
                    break;
                }

            } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
                len = int.parse(HEX.encode(br.sublist(0, 3)), radix: 16); //read size of data (4 bytes)
                buf = br.sublist(pos, len); //read the amount of data specified by "len"
                pos = pos + len;

                _chunks.add(ScriptChunk(
                    buf,
                    len,
                    opcodenum
                ));

                if (pos + len >= br.length) {
                    break;
                }
            } else {
                _chunks.add(ScriptChunk(
                    [],
                    0,
                    opcodenum
                ));
            }
        };

        _convertChunksToByteArray();
    }

    _processChunks(String script) {
        if (script
            .trim()
            .isEmpty) {
            return;
        }

        var tokenList = script.split(" "); //split on spaces
        tokenList.removeWhere((token) =>
        token
            .trim()
            .isEmpty);

        //encode tokens, leaving non-token elements intact
        for (var index = 0; index < tokenList.length;) {
            var token = tokenList[index];

            //allow for cases where script author drops OP_ prefix
//            if (OpCodes.opcodeMap.containsKey("OP_${token}")) {
//                token = "OP_${token}";
//            }

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
                _chunks.add(ScriptChunk([], 0, opcodenum));
                index = index + 1; //step by one
            }
        }
    }

    Uint8List get buffer {
        return this._byteArray;
    }

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
            if (OpCodes.opcodeMap[token.trim()] == null && OpCodes.opcodeMap["OP_${token.trim()}"] == null) { //if the token is not in the opCodeMap, it's data

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
                if (token.trim().startsWith("OP_")) {
                    encodedToken = OpCodes.opcodeMap[token.trim()].toRadixString(16);
                } else {
                    encodedToken = OpCodes.opcodeMap["OP_${token.trim()}"].toRadixString(16);
                }
            }
            return encodedToken;
        });

        //remove spaces. conc
        String hex = encodedList.fold("", (prev, elem) => prev + elem);

        this._byteArray = HEX.decode(hex);
    }

    //serialize the script to HEX
    String toHex() {
        return HEX.encode(this._byteArray);
    }

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

    //FIXME: Implement !
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
                    // A few cases where the opcode name differs from reverseMap
                    // aside from 1 to 16 data pushes.
                    if (opcodenum == 0) {
                        // OP_0 -> 0
                        str = str + ' 0';
                    } else if (opcodenum == 79) {
                        // OP_1NEGATE -> 1
                        str = str + ' -1';
                    } else {
                        str = str + ' ' + opcodenum.toRadixString(16);
                    }
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
                    str = str + ' ' + chunk.len.toRadixString(16) + ' ' + HEX.encode(chunk.buf);
                } else {
                    str = str + ' ' + chunk.len.toString() + ' ' + '0x' + HEX.encode(chunk.buf);
                }
            }
        }
        return str;
    }


    add(obj) {
        this._addByType(obj, false);
        return this;
    }

    _addByType(obj, prepend) {
        if (obj is String) {
            this._addOpcode(obj, prepend);
        } else if (obj is num) {
            this._addOpcode(obj, prepend);
        } else if (obj is List<int>) {
            this._addBuffer(obj, prepend);
        }
        /*else if (obj instanceof Script) {
            this.chunks = this.chunks.concat(obj.chunks)
        } else if (typeof obj === 'object') {
            this._insertAtPosition(obj, prepend)
        }*/ else {
            throw new ScriptException('Invalid script chunk');
        }
    }


    _addBuffer(List<int> buf, prepend) {
        var opcodenum;
        var len = buf.length;
        if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
            opcodenum = len;
        } else if (len < pow(2, 8)) {
            opcodenum = OpCodes.OP_PUSHDATA1;
        } else if (len < pow(2, 16)) {
            opcodenum = OpCodes.OP_PUSHDATA2;
        } else if (len < pow(2, 32)) {
            opcodenum = OpCodes.OP_PUSHDATA4;
        } else {
            throw new ScriptException('You can\'t push that much data');
        }

        this._insertAtPosition(ScriptChunk(buf, len, opcodenum), prepend);
    }

    _insertAtPosition(ScriptChunk chunk, bool prepend) {
        if (prepend) {
            this._chunks.insert(0, chunk);
        } else {
            this._chunks.add(chunk);
        }
    }

    _addOpcode(opcode, prepend) {
        int op;
        if (opcode is num) {
            op = opcode;
        } else if (opcode is String && OpCodes.opcodeMap.containsKey(opcode)) {
            op = OpCodes.opcodeMap[opcode];
        }

        ScriptChunk chunk = ScriptChunk([], 0, op);
        this._insertAtPosition(chunk, prepend);
    }

    @override
    String buildScript() {
        return "";
    }
}

