import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:hex/hex.dart';
import 'dart:math';
import '../exceptions.dart';
import 'opcodes.dart';
import 'package:buffer/buffer.dart';

/// Utility class to represent a parsed 'token' in the encoded script.
class ScriptChunk {

    List<int> _buf;
    int _len;
    int _opcodenum;

    ///Construct a  ScriptChunk
    ///
    /// [_buf] - Buffer containing data in case of OP_PUSHDATA
    ///
    /// [_len] - length of _buf
    ///
    /// [_opcodenum] - Bitcoin script OpCode. See [OpCodes].
    ///
    ScriptChunk(this._buf, this._len, this._opcodenum);

    /// Returns this script chunk's numeric opcode
    ///
    int get opcodenum => _opcodenum;

    /// Sets this script chunk's numeric opcode
    ///
    set opcodenum(int value) {
        _opcodenum = value;
    }

    /// Returns the length of the buffer in case of PUSHDATAx instruction. Zero otherwise.
    ///
    int get len => _len;

    /// Sets the length of data contained in PUSHDATAx instruction. Zero otherwise.
    ///
    set len(int value) {
        _len = value;
    }

    /// Returns the byte array containing the data from a PUSHDATAx instruction.
    ///
    List<int> get buf => _buf;

    /// Sets the byte array of representing PUSHDATAx instruction.
    ///
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


/// Bitcoin has a built-in scripting language. This class allows one to easily move
/// between human-readable instructions and internal hexadecimal representations of bitcoin script.
///
/// See : https://en.bitcoin.it/wiki/Script
///
class SVScript with ScriptBuilder {

    final String _script = '';

    List<ScriptChunk> _chunks = [];

    Uint8List _byteArray = Uint8List(0);

    /// Constructs a  Script instance by parsing the human-readable form of Script OP_CODES.
    ///
    /// E.g.
    /// ```
    /// var script = SVScript.fromString('OP_0 OP_PUSHDATA4 3 0x010203 OP_0');
    /// ```
    SVScript.fromString(String script){
        _processChunks(script);
        _convertChunksToByteArray();
    }

    /// Constructs a  Script instance by parsing a hexadecimal form of Script.
    ///
    /// E.g.
    /// ```
    /// var script = SVScript.fromHex('76a914f4c03610e60ad15100929cc23da2f3a799af172588ac');
    /// ```
    ///
    SVScript.fromHex(String script){
        _processBuffer(HEX.decode(script));
    }


    /// Constructs a  Script instance from a list of [ScriptChunk]s.
    SVScript.fromChunks(List<ScriptChunk> chunks) {
        _chunks = chunks;
        _convertChunksToByteArray();
    }

    /// Constructs a  Script instance by parsing a byte buffer representing a script.
    ///
    /// *NOTE:* The buffer is a bytearray representation of the script's hexadecimal string form.
    SVScript.fromByteArray(Uint8List buffer) {
        _processBuffer(buffer);
    }

    /// Constructs a  Script instance by parsing a byte buffer representing a script.
    ///
    /// *NOTE:* Same constructor as [fromByteArray]. Different name.
    SVScript.fromBuffer(Uint8List buffer) {
        _processBuffer(buffer);
    }

    /// Default constructor. Processing in this constructor is used by subclasses to bootstrap their internals.
    SVScript() {
        _processChunks(buildScript());
        _convertChunksToByteArray();
    }

    /// This constructor is *only* used by the Script Interpreter test vectors at the moment.
    /// Bitcoind test vectors are rather special snowflakes so we made a special constructor just for them.
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
            if (token.startsWith('0x')) {
                var hex = token.substring(2).replaceAll(',', '');
                bw.write(HEX.decode(hex));
            } else if (token[0] == '\'') {
                String tstr = token.substring(1, token.length - 1);
                tbuf = SVScript()
                    .add(utf8.encode(tstr))
                    .buffer;
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
//                var script = Script().add( BN(token).toScriptNumBuffer())
//                tbuf = script.toBuffer()
//                bw.write(tbuf)

                var script = SVScript()
                    ..add(Uint8List.fromList(toScriptNumBuffer(BigInt.parse(token))));
                tbuf = script.buffer;
                bw.write(tbuf);
            } else {
                throw  ScriptException('Could not determine type of script value');
            }
        }

        _processBuffer(bw.toBytes());
    }



    _convertChunksToByteArray() {
//        String chunkString = _chunks.fold('', (prev, elem) => prev + _chunkToString(elem, type: 'asm'));
//        _byteArray = Uint8List.fromList(HEX.decode(chunkString.replaceAll(' ', '')));

        var bw =  ByteDataWriter();

        for (var i = 0; i < _chunks.length; i++) {
            var chunk = _chunks[i];
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

        _byteArray = bw.toBytes();
    }


    _processBuffer(Uint8List buffer) {
        ByteDataReader byteDataReader = ByteDataReader();
        byteDataReader.add(buffer);
        while (byteDataReader.remainingLength > 0) {
            try {
                var opcodenum = byteDataReader.readUint8();
                int len;
                Uint8List buf;
                if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
                    len = opcodenum;
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : Uint8List(0);
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
                    len = byteDataReader.readUint8();
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : Uint8List(0);
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
                    len = byteDataReader.readUint16(Endian.little);
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : Uint8List(0);

                    //Construct a scriptChunk
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
                    len = byteDataReader.readUint32(Endian.little);
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : Uint8List(0);

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
            } catch (e) {

                throw  ScriptException(HEX.encode(buffer));
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

        var tokenList = script.split(' '); //split on spaces
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
                    throw  ScriptException('Invalid script: ' + script);
                }
            } else if (opcodenum == OpCodes.OP_PUSHDATA1 ||
                opcodenum == OpCodes.OP_PUSHDATA2 ||
                opcodenum == OpCodes.OP_PUSHDATA4) {
                if (tokenList[index + 2].substring(0, 2) != '0x') {
                    throw  ScriptException('Pushdata data must start with 0x');
                }
                _chunks.add(ScriptChunk(HEX.decode(tokenList[index + 2].substring(2)), int.parse(tokenList[index + 1], radix: 16), opcodenum));
                index = index + 3; //step by three
            } else {
                _chunks.add(ScriptChunk([], 0, opcodenum));
                index = index + 1; //step by one
            }
        }
    }


    /// Render this script in it's human-readable form
    String toString() {
        if (_chunks.isNotEmpty) {
            return _chunks.fold('', (String prev, ScriptChunk chunk) => prev + _chunkToString(chunk)).trim();
        }

        return _script;
    }

    /// Renders this script in it's hexadecimal form as a String
    String toHex() {
        return HEX.encode(_byteArray);
    }

    /// Returns *true* if this script only performs PUSHDATA operations
    bool isPushOnly() {
        return _chunks.fold(true, (prev, chunk) {
            return prev && (chunk.opcodenum <= OpCodes.OP_16 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA1 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA2 ||
                chunk.opcodenum == OpCodes.OP_PUSHDATA4);
        });
    }

    /// Returns *true* if this script matches the Pay-To-Public-Key-Hash template
    bool isScriptHashOut() {
        var buf = buffer;
        return (buf.length == 23 &&
        buf[0] == OpCodes.OP_HASH160 &&
        buf[1] == 0x14 &&
        buf[buf.length - 1] == OpCodes.OP_EQUAL);
    }

    /// Return this script in it's hexadecimal form as a bytearray
    Uint8List get buffer {
        _convertChunksToByteArray();
        return Uint8List.fromList(_byteArray);
    }

    /// Returns this script's internal representation as a list of [ScriptChunk]s
    List<ScriptChunk> get chunks => _chunks;

    /// Checks to see if the PUSHDATA instruction is using the *smallest* pushdata opcode it can.
    ///
    /// [i] - Index of ScriptChunk. This should be a pushdata instruction.
    ///
    /// Returns true if the *smallest* pushdata opcode was used.
    bool checkMinimalPush(int i) {
        var chunk = _chunks[i];
        var buf = chunk.buf;
        var opcodenum = chunk.opcodenum;

        if (buf.length == 0) {
            // Could have used OP_0.
            return opcodenum == OpCodes.OP_0;
        } else if (buf.length == 1 && buf[0] >= 1 && buf[0] <= 16) {
            // Could have used OP_1 .. OP_16.
            return opcodenum == OpCodes.OP_1 + (buf[0] - 1);
        } else if (buf.length == 1 && buf[0] == 0x81) {
            // Could have used OP_1NEGATE
            return opcodenum == OpCodes.OP_1NEGATE;
        } else if (buf.length <= 75) {
            // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
            return opcodenum == buf.length;
        } else if (buf.length <= 255) {
            // Could have used OP_PUSHDATA.
            return opcodenum == OpCodes.OP_PUSHDATA1;
        } else if (buf.length <= 65535) {
            // Could have used OP_PUSHDATA2.
            return opcodenum == OpCodes.OP_PUSHDATA2;
        }
        return true;
    }


    /// Removes [ScriptChunk]s from the script and optionally inserts  [ScriptChunk]s.
    ///
    /// `index` - starting index for items to be removed.
    ///
    /// `howMany` - the number of items to be removed.
    ///
    /// `values`  - an optional List of  items to insert; null if no items need insertion
    List<ScriptChunk> splice(int index, int howMany, {List<ScriptChunk> values}) {
        List<ScriptChunk> buffer = List.from(_chunks);

        List<ScriptChunk> removedItems = buffer.getRange(index, index+howMany).toList();
        buffer.removeRange(index, index+howMany);

        if (values != null) {
            buffer.insertAll(index, values);
        }
        _chunks = List.from(buffer);

        return removedItems;

    }


    /// Strips all OP_CODESEPARATOR instructions from the script.
    SVScript removeCodeseparators() {
        var chunks = List<ScriptChunk>();
        for (var i = 0; i < _chunks.length; i++) {
            if (_chunks[i].opcodenum != OpCodes.OP_CODESEPARATOR) {
                chunks.add(_chunks[i]);
            }
        }
        _chunks = chunks;
        _convertChunksToByteArray();
        return this;
    }

    /// Searches for a subscript within the current script and deletes it.
    SVScript findAndDelete(SVScript tmpScript) {

        var buf = List<int>.from(tmpScript.buffer);
        var hex = HEX.encode(buf);
        for (var i = 0; i < _chunks.length; i++) {
            var script2 = SVScript.fromChunks([_chunks[i]]);
            var buf2 = script2.buffer;
            var hex2 = HEX.encode(buf2);
            if (hex == hex2) {
                splice(i, 1);
            }
        }
        return this;
    }


    ///Appends an item to the Script. Used by the Interpreter. Should *not* be useful for everyday wallet development.
    ///
    /// Implementation of [_addByType] looks as follows:
    ///
    /// ```
    /// if (obj is String) {
    ///     _addOpcode(obj, prepend);
    /// } else if (obj is num) {
    ///     _addOpcode(obj, prepend);
    /// } else if (obj is List<int>) {
    ///     _addBuffer(obj, prepend);
    /// }else {
    ///     throw  ScriptException('Invalid script chunk');
    /// }
    /// ```
    ///
    SVScript add(obj) {
        _addByType(obj, false);
        return this;
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



    void _addByType(obj, prepend) {
        if (obj is String) {
            _addOpcode(obj, prepend);
        } else if (obj is num) {
            _addOpcode(obj, prepend);
        } else if (obj is List<int>) {
            _addBuffer(obj, prepend);
        }
        /*else if (obj instanceof Script) {
            chunks = chunks.concat(obj.chunks)
        } else if (typeof obj === 'object') {
            _insertAtPosition(obj, prepend)
        }*/ else {
            throw  ScriptException('Invalid script chunk');
        }
    }


    void _addBuffer(List<int> buf, prepend) {
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
            throw  ScriptException('You can\'t push that much data');
        }

        _insertAtPosition(ScriptChunk(buf, len, opcodenum), prepend);
    }

    void _insertAtPosition(ScriptChunk chunk, bool prepend) {
        if (prepend) {
            _chunks.insert(0, chunk);
        } else {
            _chunks.add(chunk);
        }
    }

    void _addOpcode(opcode, prepend) {
        int op;
        if (opcode is num) {
            op = opcode;
        } else if (opcode is String && OpCodes.opcodeMap.containsKey(opcode)) {
            op = OpCodes.opcodeMap[opcode];
        }

        ScriptChunk chunk = ScriptChunk([], 0, op);
        _insertAtPosition(chunk, prepend);
    }

    /// Currently used by subclasses. A more elegant way is needed to build specialised Script subclasses.
    @override
    String buildScript() {
        return '';
    }
}

