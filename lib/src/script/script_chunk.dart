import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/preconditions.dart';
import 'package:hex/hex.dart';

/// Utility class to represent a parsed 'token' in the encoded script.
class ScriptChunk {

  List<int>? _buf = null;
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
  List<int>? get buf => _buf;

  /// Sets the byte array of representing PUSHDATAx instruction.
  ///
  set buf(List<int>? value) {
    _buf = value;
  }

  bool equalsOpCode(int opcode) {
    return opcode == _opcodenum;
  }

  /**
   * If this chunk is a single byte of non-pushdata content (could be OP_RESERVED or some invalid Opcode)
   */
  bool isOpCode() {
    return _opcodenum > OpCodes.OP_PUSHDATA4;
  }

  /**
   * Returns true if this chunk is pushdata content, including the single-byte pushdatas.
   */
  bool isPushData() {
    return _opcodenum <= OpCodes.OP_16;
  }

  /** If this chunk is an OP_N opcode returns the equivalent integer value. */
  int decodeOpN() {
    return SVScript.decodeFromOpN(_opcodenum);
  }

  int size() {
    final int opcodeLength = 1;

    int pushDataSizeLength = 0;
    if (_opcodenum == OpCodes.OP_PUSHDATA1) pushDataSizeLength = 1;
    else if (_opcodenum == OpCodes.OP_PUSHDATA2) pushDataSizeLength = 2;
    else if (_opcodenum == OpCodes.OP_PUSHDATA4) pushDataSizeLength = 4;

    final int dataLength = _buf == null ? 0 : _buf!.length;

    return opcodeLength + pushDataSizeLength + dataLength;
  }


  /// Checks to see if the PUSHDATA instruction is using the *smallest* pushdata opcode it can.
  ///
  /// Returns true if the *smallest* pushdata opcode was used.
  bool checkMinimalPush() {
    PreConditions.assertTrue(isPushData());

    if (_buf == null ) {
      // Could have used OP_0.
      return (_opcodenum == OpCodes.OP_0);
    } else if (_buf != null && _buf!.length == 1 && _buf![0] >= 1 && _buf![0] <= 16) {
      // Could have used OP_1 .. OP_16.
      return _opcodenum == OpCodes.OP_1 + (_buf![0] - 1);
    } else if (_buf != null && _buf!.length == 1 && _buf![0] == 0x81) {
      // Could have used OP_1NEGATE
      return _opcodenum == OpCodes.OP_1NEGATE;
    } else if (_buf != null && _buf!.length <= 75) {
      // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
      return _opcodenum == _buf!.length;
    } else if (_buf != null && _buf!.length <= 255) {
      // Could have used OP_PUSHDATA.
      return _opcodenum == OpCodes.OP_PUSHDATA1;
    } else if (_buf != null && _buf!.length <= 65535) {
      // Could have used OP_PUSHDATA2.
      return _opcodenum == OpCodes.OP_PUSHDATA2;
    }
    return true;
  }

    String toEncodedString(bool asm){
        StringBuffer str = new StringBuffer();
        if (_buf == null || (_buf != null && _buf!.length <= 0)) {

            // no data chunk
            if (!OpCodes.getOpCodeName(opcodenum).startsWith("NON_OP")) {
                if (asm) {
                    // A few cases where the opcode name differs from reverseMap
                    // aside from 1 to 16 data pushes.
                    if (opcodenum == 0) {
                        // OP_0 -> 0
                        str.write("0");
                    } else if (opcodenum == 79) {
                        // OP_1NEGATE -> 1
                        str.write("-1");
                    } else {
                        str.write( OpCodes.getOpCodeName(opcodenum));
                    }
                } else {
                    str.write(  OpCodes.getOpCodeName(opcodenum));
                }
            } else {
                String numstr =  HEX.encode([opcodenum]);

                //uneven numbers get padded with a leading zero
                if (numstr.length % 2 != 0) {
                    numstr = "0" + numstr;
                }
                if (asm) {
                    str.write( numstr);
                } else {
                    str.write("0x" + numstr);
                }
            }
        } else {
            // data chunk
            if (!asm && (opcodenum == OpCodes.OP_PUSHDATA1 ||
                    opcodenum == OpCodes.OP_PUSHDATA2 ||
                    opcodenum == OpCodes.OP_PUSHDATA4)) {
                str.write(  OpCodes.getOpCodeName(opcodenum) + " ");
            }
            if (_buf != null && _buf!.length > 0) {
                if (asm) {
                    str.write(HEX.encode(_buf!));
                } else {
                    str.write("${_buf?.length} 0x${HEX.encode(_buf!)}");
                }
            }
        }
        return str.toString();
    }


}
