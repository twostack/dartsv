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
import 'package:buffer/buffer.dart';

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

    Uint8List _byteArray = Uint8List(0);

    //FIXME: I'm not convinced this does what I think it does. Recheck !
    SVScript.fromString(String script){
        this._processChunks(script);
    }

    SVScript.fromHex(String script){
        this._script = script;
        parse(script);
    }


    _convertChunksToByteArray(){
//        String chunkString = this._chunks.fold("", (prev, elem) => prev + _chunkToString(elem, type: 'asm'));
//        this._byteArray = Uint8List.fromList(HEX.decode(chunkString.replaceAll(' ', '')));

        var bw = new ByteDataWriter();

        for (var i = 0; i < this._chunks.length; i++) {
            var chunk = this._chunks[i];
            var opcodenum = chunk.opcodenum;
            bw.writeUint8(chunk.opcodenum);
            if (chunk.buf.isNotEmpty) {
                if (opcodenum < OpCodes.OP_PUSHDATA1) {
                    bw.write(chunk.buf);
                } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
                    bw.writeUint8(chunk.len);
                    bw.write(chunk.buf);
                } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
                    bw.writeUint16(chunk.len, Endian.little);
                    bw.write(chunk.buf);
                } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
                    bw.writeUint32(chunk.len, Endian.little);
                    bw.write(chunk.buf);
                }
            }
        }

        this._byteArray = bw.toBytes();

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

    SVScript.fromBitcoindString(String str) {
        var bw = ByteDataWriter();
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
                bw.write(HEX.decode(hex));
            } else if (token[0] == '\'') {
                String tstr = token.substring(1, token.length - 1);
                tbuf = SVScript().add(utf8.encode(tstr)).buffer;
                bw.write(tbuf);
            } else if (OpCodes.opcodeMap.containsKey("OP_${token}")) {
                opstr = 'OP_' + token;
                opcodenum = OpCodes.opcodeMap[opstr];
                bw.writeUint8(opcodenum);
            } else if (OpCodes.opcodeMap[token] is num) {
                opstr = token;
                opcodenum = OpCodes.opcodeMap[opstr];
                bw.writeUint8(opcodenum);
            } else if (BigInt.tryParse(token) != null) {

//                var script = Script().add(new BN(token).toScriptNumBuffer())
//                tbuf = script.toBuffer()
//                bw.write(tbuf)

                var script = SVScript()
                    ..add(Uint8List.fromList(toScriptNumBuffer(BigInt.parse(token))));
                tbuf = script.buffer;
                bw.write(tbuf);
            } else {
                throw new ScriptException('Could not determine type of script value');
            }
        }

        _processBuffer(bw.toBytes());
    }

    SVScript.fromBuffer(Uint8List buffer) {
        _processBuffer(buffer);
    }

    _processBuffer(Uint8List buffer){

        ByteDataReader byteDataReader = ByteDataReader();
        byteDataReader.add(buffer);
        while (byteDataReader.remainingLength > 0){
            try {
                var opcodenum = byteDataReader.readUint8();
                int len;
                Uint8List buf;
                if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
                    len = opcodenum;
                    _chunks.add(ScriptChunk(
                        byteDataReader.read(len, copy: true),
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
                    len = byteDataReader.readUint8();
                    buf = byteDataReader.read(len, copy: true);
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
                    len = byteDataReader.readUint16(Endian.little);
                    buf = byteDataReader.read(len, copy: true);

                    //Construct a scriptChunk
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));


                } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
                    len = byteDataReader.readUint32(Endian.little);
                    buf = byteDataReader.read(len, copy: true);

                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));

                } else {
                    _chunks.add(ScriptChunk(
                        [],
                        0,
                        opcodenum
                    ));
                }
            }catch (e) {
                throw new ScriptException(HEX.encode(buffer));
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

        _convertChunksToByteArray();
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
        } else if (obj is Uint8List) {
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

