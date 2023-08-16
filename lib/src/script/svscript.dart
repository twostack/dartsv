import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/interpreter_v2.dart';
import 'package:dartsv/src/script/script_error.dart';
import 'package:dartsv/src/transaction/preconditions.dart';
import 'package:hex/hex.dart';
import 'dart:math';
import '../exceptions.dart';
import 'opcodes.dart';
import 'package:buffer/buffer.dart';
import 'script_chunk.dart';


enum VerifyFlag {
  P2SH, // Enable BIP16-style subscript evaluation.
  STRICTENC, // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
  DERSIG, // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP66 rule 1)
  LOW_S, // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
  NULLDUMMY, // Verify dummy stack item consumed by CHECKMULTISIG is of zero-length.
  SIGPUSHONLY, // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
  MINIMALDATA, // Require minimal encodings for all push operations and number encodings
  DISCOURAGE_UPGRADABLE_NOPS, // Discourage use of NOPs reserved for upgrades (NOP1-10)
  CLEANSTACK, // Require that only a single stack element remains after evaluation.
  CHECKLOCKTIMEVERIFY, // Enable CHECKLOCKTIMEVERIFY operation
  CHECKSEQUENCEVERIFY,
  SIGHASH_FORKID,
  MONOLITH_OPCODES, // May 15, 2018 Hard fork
  UTXO_AFTER_GENESIS,
  MINIMALIF,
  NULLFAIL,
  COMPRESSED_PUBKEYTYPE
}


/// Bitcoin has a built-in scripting language. This class allows one to easily move
/// between human-readable instructions and internal hexadecimal representations of bitcoin script.
///
/// See : https://en.bitcoin.it/wiki/Script
///
class SVScript {

    final String _script = '';

    List<ScriptChunk> _chunks = [];

    List<int> _byteArray = List<int>.empty(growable: true);

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
    SVScript.fromByteArray(List<int> buffer) {
        _processBuffer(buffer);
    }

    /// Constructs a  Script instance by parsing a byte buffer representing a script.
    ///
    /// *NOTE:* Same constructor as [fromByteArray]. Different name.
    SVScript.fromBuffer(List<int> buffer) {
        _processBuffer(buffer);
    }

    /// Default constructor. Processing in this constructor is used by subclasses to bootstrap their internals.
    SVScript() { }

    /// This constructor is *only* used by the Script Interpreter test vectors at the moment.
    /// Bitcoind test vectors are rather special snowflakes so we made a special constructor just for them.
    // SVScript.fromBitcoindString(String str) {
    //
    //   _chunks = _stringToChunks(str);
    //
    //     // _processBuffer(bw.toBytes());
    // }

    SVScript.fromBitcoindString(String str){

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
        } else if (OpCodes.opcodeMap.containsKey("OP_${token.toUpperCase()}")) {
          opstr = 'OP_' + token;
          opcodenum = OpCodes.opcodeMap[opstr]!;
          bw.writeUint8(opcodenum);
        } else if (OpCodes.opcodeMap[token] is num) {
          opstr = token;
          opcodenum = OpCodes.opcodeMap[opstr]!;
          bw.writeUint8(opcodenum);
        } else if (BigInt.tryParse(token) != null) {
          var script = SVScript()
            ..add(Uint8List.fromList(castToBuffer(BigInt.parse(token))));
          tbuf = script.buffer;
          bw.write(tbuf);
        } else {
          throw  ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'Could not determine type of script value');
        }
      }

      _processBuffer(bw.toBytes());
    }



    SVScript.fromASM(String str) {
      var script = new SVScript();
      _chunks = [];

      var tokens = str.split(' ');
      for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i];
      var opcode = OpCodes.opcodeMap[token];
      var opcodenum = opcode;

      // we start with two special cases, 0 and -1, which are handled specially in
      // toASM. see _chunkToString.
      if (token == '0') {
        opcodenum = 0;
        _chunks.add(ScriptChunk([], 0, opcodenum));
      } else if (token == '-1') {
        opcodenum = OpCodes.OP_1NEGATE;
        _chunks.add(ScriptChunk([], 0, opcodenum));
      } else if (opcodenum == null) {
//          var buf = Buffer.from(tokens[i], 'hex')
        var buf = HEX.decode(tokens[i]);
        if (HEX.encode(buf) != tokens[i]) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'invalid hex string in script');
        }
        var len = buf.length;
        if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
          opcodenum = len;
        } else if (len < pow(2, 8)) {
          opcodenum = OpCodes.OP_PUSHDATA1;
        } else if (len < pow(2, 16)) {
          opcodenum = OpCodes.OP_PUSHDATA2;
        } else if (len < pow(2, 32)) {
          opcodenum = OpCodes.OP_PUSHDATA4;
        }

        _chunks.add(ScriptChunk(buf, buf.length, opcodenum!));
      } else {
        _chunks.add(ScriptChunk([], 0, opcodenum));
      }
    }

  }

  List<ScriptChunk> _stringToChunks(String script) {
    if (script.trim().isEmpty) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,  " - Unexpected end of script");
    }

    List<ScriptChunk> localChunks = List<ScriptChunk>.empty(growable: true);

    List<String> tokenList = script.split(" "); //split on spaces
    tokenList.removeWhere((token) => token.trim().isEmpty);

    //encode tokens, leaving non-token elements intact
    for (int index = 0; index < tokenList.length;) {
      String token = tokenList[index];

      int opcodenum = OpCodes.OP_INVALIDOPCODE;
      if (token.startsWith("OP_")) {
        opcodenum = OpCodes.getOpCode(token.replaceFirst("OP_", ""));
      } else {
        opcodenum = opcodenum.toInt(); //???
      }

      if (opcodenum == OpCodes.OP_INVALIDOPCODE) {
        try {
          opcodenum = int.parse(token);
          if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
            var data = HEX.decode(tokenList[index + 1].substring(2));
            ScriptChunk newChunk = ScriptChunk(data, data.length, opcodenum);
            localChunks.add(newChunk);
          }
          index = index + 2; //step by two
        } on Exception catch (ex) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,  ex.toString());
        }
      } else if (opcodenum == OpCodes.OP_PUSHDATA1 || opcodenum == OpCodes.OP_PUSHDATA2 || opcodenum == OpCodes.OP_PUSHDATA4) {
        if (!(tokenList[index + 2].substring(0, 2) == "0x")) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,  " - Pushdata data must start with 0x");
        }
        List<int> data = HEX.decode(tokenList[index + 2].substring(2));
        localChunks.add(ScriptChunk(data, data.length, opcodenum));
        index = index + 3; //step by three
      } else {
        localChunks.add(ScriptChunk([], 0, opcodenum));
        index = index + 1; //step by one
      }
    }

    return localChunks;
  }

  _convertChunksToByteArray() {

        var stream =  ByteDataWriter();

        // for (var i = 0; i < _chunks.length; i++) {
        //     var chunk = _chunks[i];
        //     var opcodenum = chunk.opcodenum;
        //     bw.writeUint8(chunk.opcodenum);
        //     if (chunk.buf.isNotEmpty) {
        //         if (opcodenum < OpCodes.OP_PUSHDATA1) {
        //             bw.write(chunk.buf);
        //         } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
        //             bw.writeUint8(chunk.len);
        //             bw.write(chunk.buf);
        //         } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
        //             bw.writeUint16(chunk.len, Endian.little);
        //             bw.write(chunk.buf);
        //         } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
        //             bw.writeUint32(chunk.len, Endian.little);
        //             bw.write(chunk.buf);
        //         }
        //     }
        //
        // }
        //
        for (ScriptChunk chunk in _chunks) {
          if (chunk.isOpCode()) {
            PreConditions.assertTrue(chunk.buf == null);
            stream.writeUint8(chunk.opcodenum);
          } else if (chunk.buf != null) {
            if (chunk.opcodenum < OpCodes.OP_PUSHDATA1) {
              PreConditions.assertTrue(chunk.buf!.length == chunk.opcodenum);
              stream.writeUint8(chunk.opcodenum);
            } else if (chunk.opcodenum == OpCodes.OP_PUSHDATA1) {
              PreConditions.assertTrue(chunk.buf!.length <= 0xFF);
              stream.writeUint8(OpCodes.OP_PUSHDATA1);
              stream.writeUint8(chunk.buf!.length);
            } else if (chunk.opcodenum == OpCodes.OP_PUSHDATA2) {
              PreConditions.assertTrue(chunk.buf!.length <= 0xFFFF);
              stream.writeUint8(OpCodes.OP_PUSHDATA2);
              stream.writeUint16(chunk.buf!.length, Endian.little);//Utils.uint16ToByteStreamLE(data.length, stream);
            } else if (chunk.opcodenum == OpCodes.OP_PUSHDATA4) {
              PreConditions.assertTrue(chunk.buf!.length <= InterpreterV2.MAX_SCRIPT_ELEMENT_SIZE);
              stream.writeUint8(OpCodes.OP_PUSHDATA4);
              stream.writeUint32(chunk.buf!.length, Endian.little);//Utils.uint32ToByteStreamLE(data.length, stream);
            } else {
              throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unimplemented");
            }
            stream.write(chunk.buf!);
          } else {
            stream.writeUint8(chunk.opcodenum); // smallNum
          }
        }

        _byteArray = stream.toBytes();
    }

  void _processBuffer(List<int> program) {

      if (program.isEmpty) return;

    _chunks = List<ScriptChunk>.empty(growable: true);
    ByteDataReader bis = ByteDataReader();
    bis.add(program);

    while (bis.remainingLength > 0) {
      int opcode = bis.readUint8();

      int dataToRead = -1;
      if (opcode >= 0 && opcode < OpCodes.OP_PUSHDATA1) {
        // Read some bytes of data, where how many is the opcode value itself.
        dataToRead = opcode;
      } else if (opcode == OpCodes.OP_PUSHDATA1) {
        if (bis.remainingLength < 1) throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, " - Unexpected end of script");
        dataToRead = bis.readUint8();
      } else if (opcode == OpCodes.OP_PUSHDATA2) {
        // Read a short, then read that many bytes of data.
        if (bis.remainingLength < 2) throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, " - Unexpected end of script");
        dataToRead = bis.readUint16(Endian.little);
      } else if (opcode == OpCodes.OP_PUSHDATA4) {
        // Read a uint32, then read that many bytes of data.
        if (bis.remainingLength < 4) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,  " - Unexpected end of script");
        dataToRead = bis.readUint32(Endian.little);
      } else {}

      if (dataToRead == -1) {
        chunks.add(ScriptChunk(null, 0, opcode));
      } else {
        if (dataToRead > bis.remainingLength)
          throw ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, " - Length of push value is not equal to length of data");

        try {
          ScriptChunk chunk;
          // List<int> data = List<int>.generate(dataToRead, (i) => 0);

          var data = bis.read(dataToRead);
          chunk = ScriptChunk(data, data.length, opcode);

          chunks.add(chunk);
        } on Exception catch (ex) {
          bis.readUint8();
        }
      }
      // Save some memory by eliminating redundant copies of the same chunk objects.
    }
  }


    /*
  _processBuffer(List<int> buffer) {
        ByteDataReader byteDataReader = ByteDataReader();
        byteDataReader.add(buffer);
        while (byteDataReader.remainingLength > 0) {
            try {
                var opcodenum = byteDataReader.readUint8();
                int len;
                List<int> buf;
                if (opcodenum > 0 && opcodenum < OpCodes.OP_PUSHDATA1) {
                    len = opcodenum;
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : [];
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA1) {
                    len = byteDataReader.readUint8();
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : [];
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA2) {
                    len = byteDataReader.readUint16(Endian.little);
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : [];

                    //Construct a scriptChunk
                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else if (opcodenum == OpCodes.OP_PUSHDATA4) {
                    len = byteDataReader.readUint32(Endian.little);
                    buf = byteDataReader.remainingLength >= len ? byteDataReader.read(len, copy: true) : [];

                    _chunks.add(ScriptChunk(
                        buf,
                        len,
                        opcodenum
                    ));
                } else {
                    _chunks.add(ScriptChunk(
                        null,
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

     */

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
                    throw  ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'Invalid script: ' + script);
                }
            } else if (opcodenum == OpCodes.OP_PUSHDATA1 ||
                opcodenum == OpCodes.OP_PUSHDATA2 ||
                opcodenum == OpCodes.OP_PUSHDATA4) {
                if (tokenList[index + 2].substring(0, 2) != '0x') {
                    throw  ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, 'Pushdata data must start with 0x');
                }
                var data = HEX.decode(tokenList[index + 2].substring(2));
                _chunks.add(ScriptChunk(data, data.length, opcodenum));
                index = index + 3; //step by three
            } else {
                _chunks.add(ScriptChunk([], 0, opcodenum));
                index = index + 1; //step by one
            }
        }
    }


    /// Render this script in it's human-readable form
    ///
    /// Parameters:
    ///
    /// [type] - options are either 'hex' or 'asm'
    ///
    String toString({type='hex'}) {
        if (!_chunks.isEmpty) {
          List<String> asmStrings = _chunks.map((chunk) => chunk.toEncodedString(type == 'asm')).toList();
          return asmStrings.fold("", (previousValue, element) => "${previousValue} ${element}").trim();
        } else {
          return "<empty>";
        }
    }

    /// Renders this script in it's hexadecimal form as a String
    String toHex() {
        _convertChunksToByteArray();
        return HEX.encode(_byteArray);
    }

    String toBitcoindString(){
        if (!_chunks.isEmpty) {
          List<String> asmStrings = _chunks.map((chunk) => chunk.toEncodedString(false)).toList();
          return asmStrings.fold("", (previousValue, element) => "${previousValue} ${element}").trim();
        } else {
          return "<empty>";
        }
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
    List<int> get buffer {
        _convertChunksToByteArray();
        return _byteArray;
    }

    /// Returns this script's internal representation as a list of [ScriptChunk]s
    List<ScriptChunk> get chunks => _chunks;



    /// Removes [ScriptChunk]s from the script and optionally inserts  [ScriptChunk]s.
    ///
    /// `index` - starting index for items to be removed.
    ///
    /// `howMany` - the number of items to be removed.
    ///
    /// `values`  - an optional List of  items to insert; null if no items need insertion
    List<ScriptChunk> splice(int index, int howMany, {List<ScriptChunk>? values}) {
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
        var chunks = <ScriptChunk>[];
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

    // String _chunkToString(ScriptChunk chunk, {type = 'hex'}) {
    //     var opcodenum = chunk.opcodenum;
    //     var asm = (type == 'asm');
    //     var str = '';
    //     if (chunk.buf.isEmpty) {
    //         if (chunk.opcodenum == null) return "";
    //
    //         // no data chunk
    //         if (OpCodes.opcodeMap.containsValue(opcodenum)) {
    //             if (asm) {
    //                 // A few cases where the opcode name differs from reverseMap
    //                 // aside from 1 to 16 data pushes.
    //                 if (opcodenum == 0) {
    //                     // OP_0 -> 0
    //                     str = str + ' 0';
    //                 } else if (opcodenum == 79) {
    //                     // OP_1NEGATE -> 1
    //                     str = str + ' -1';
    //                 } else {
    //                     str = str + ' ' + OpCodes.fromNum(opcodenum);
    //                 }
    //             } else {
    //                 str = str + ' ' + OpCodes.fromNum(opcodenum);
    //             }
    //         } else {
    //             var numstr = opcodenum.toRadixString(16);
    //             if (numstr.length % 2 != 0) {
    //                 numstr = '0' + numstr;
    //             }
    //             if (asm) {
    //                 str = str + ' ' + numstr;
    //             } else {
    //                 str = str + ' ' + '0x' + numstr;
    //             }
    //         }
    //     } else {
    //         // data chunk
    //         if (!asm && (opcodenum == OpCodes.OP_PUSHDATA1 ||
    //             opcodenum == OpCodes.OP_PUSHDATA2 ||
    //             opcodenum == OpCodes.OP_PUSHDATA4)) {
    //             str = str + ' ' + OpCodes.fromNum(opcodenum);
    //         }
    //         if (chunk.len > 0) {
    //             if (asm) {
    //                 str = str + ' ' + HEX.encode(chunk.buf);
    //             } else {
    //                 str = str + ' ' + chunk.len.toString() + ' ' + '0x' + HEX.encode(chunk.buf);
    //             }
    //         }
    //     }
    //     return str;
    // }
    //


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
            throw  ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'Invalid script chunk');
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
            throw  ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'You can\'t push that much data');
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
            op = opcode as int;
        } else if (opcode is String && OpCodes.opcodeMap.containsKey(opcode)) {
            op = OpCodes.opcodeMap[opcode]!;
        }else{
            op = OpCodes.OP_INVALIDOPCODE;
        }

        if (op != OpCodes.OP_INVALIDOPCODE) {
          ScriptChunk chunk = ScriptChunk([], 0, op);
          _insertAtPosition(chunk, prepend);
        }
    }


    static int decodeFromOpN(int opcode) {
      PreConditions.assertTrueWithMessage(opcode == 0 || opcode == 79 || opcode >= 81 && opcode <= 96, "decodeFromOpN called on non OP_N opcode:${OpCodes.fromNum(opcode)}");
      if (opcode == 0) {
        return 0;
      } else {
        return opcode == 79 ? -1 : opcode + 1 - 81;
      }
    }

    static int encodeToOpN(int value) {
      PreConditions.assertTrueWithMessage(value >= -1 && value <= 16, "encodeToOpN called for ${value} which we cannot encode in an opcode.");
      if (value == 0) {
        return 0;
      } else {
        return value == -1 ? 79 : value - 1 + 81;
      }
    }

  static int getSigOpCount(List<ScriptChunk> chunks, bool accurate) {
    int sigOps = 0;
    int lastOpCode = OpCodes.OP_INVALIDOPCODE;
    for (ScriptChunk chunk in chunks) {
      if (chunk.isOpCode()) {
        switch (chunk.opcodenum) {
          case OpCodes.OP_CHECKSIG:
          case OpCodes.OP_CHECKSIGVERIFY:
            sigOps++;
            break;
          case OpCodes.OP_CHECKMULTISIG:
          case OpCodes.OP_CHECKMULTISIGVERIFY:
            if (accurate && lastOpCode >= OpCodes.OP_1 && lastOpCode <= OpCodes.OP_16)
              sigOps += decodeFromOpN(lastOpCode);
            else
              sigOps += 20;
            break;
          default:
            break;
        }
        lastOpCode = chunk.opcodenum;
      }
    }
    return sigOps;
  }

    /**
     * Returns the script bytes of inputScript with all instances of the specified script object removed
     */
  static List<int> removeAllInstancesOf( List<int> inputScript, List<int> chunkToRemove) {
    // We usually don't end up removing anything
    var writer = ByteDataWriter(bufferLength : inputScript.length);

    int cursor = 0;
    var reader = ByteDataReader();
    while (cursor < inputScript.length) {
      bool skip = ListEquality().equals(inputScript.sublist(cursor), chunkToRemove);

      int opcode = inputScript[cursor++] & 0xFF;
      int additionalBytes = 0;
      if (opcode >= 0 && opcode < OpCodes.OP_PUSHDATA1) {
        additionalBytes = opcode;
      } else if (opcode == OpCodes.OP_PUSHDATA1) {
        additionalBytes = (0xFF & inputScript[cursor]) + 1;
      } else if (opcode == OpCodes.OP_PUSHDATA2) {
        additionalBytes = readUint16(inputScript, cursor) + 2;
      } else if (opcode == OpCodes.OP_PUSHDATA4) {
        additionalBytes = readUint32(inputScript, cursor) + 4;
      }
      if (!skip) {
        writer.writeUint8(opcode);
        // Arrays.copyOfRange( inputScript, cursor, cursor + additionalBytes);
        // List<int> rangeCopy = List<int>.generate(cursor + additionalBytes, (i) => 0);
        // rangeCopy.setRange(0, cursor + additionalBytes, inputScript, cursor);
        writer.write(inputScript.sublist(cursor, cursor + additionalBytes));
      }
      cursor += additionalBytes;
    }
    return writer.toBytes();
  }


  /**
     * Returns the script bytes of inputScript with all instances of the given op code removed
     */
  static List<int> removeAllInstancesOfOp(List<int> inputScript, int opCode) {
    return removeAllInstancesOf(inputScript, [opCode]);
  }

  static void writeBytes(ByteDataWriter os, List<int> buf) {
    if (buf.length < OpCodes.OP_PUSHDATA1) {
      os.writeUint8(buf.length);
      os.write(buf);
    } else if (buf.length < 256) {
      os.writeUint8(OpCodes.OP_PUSHDATA1);
      os.writeUint8(buf.length);
      os.write(buf);
    } else if (buf.length < 65536) {
      os.writeUint8(OpCodes.OP_PUSHDATA2);
      os.writeUint16(buf.length, Endian.little);
      os.write(buf);
    } else {
      throw Exception("Unimplemented");
    }
  }
}
