import 'dart:collection';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/preconditions.dart';

import '../script/script_chunk.dart';

class ScriptBuilder {
  List<ScriptChunk> _chunks = List.empty(growable: true);

  ScriptBuilder() {}

  ScriptBuilder.fromScript(SVScript template) {
    this._chunks = List.from(template.chunks); //take a copy of the chunks
  }

  ScriptBuilder addChunk(ScriptChunk chunk) {
    return insertChunk(this._chunks.length, chunk);
  }

  ScriptBuilder insertChunk(int index, ScriptChunk chunk) {
    _chunks.insert(index, chunk);
    return this;
  }

  ScriptBuilder opCode(int opcode) {
    return opCodeAtIndex(_chunks.length, opcode);
  }

  ScriptBuilder opCodeAtIndex(int index, int opcode) {
    PreConditions.assertTrue(opcode == 0 || opcode > 78);
    return insertChunk(index, ScriptChunk(List.empty(), 0, opcode));
  }

  ScriptBuilder addData(Uint8List data) {
    return data.length == 0 ? smallNum(0) : insertData(_chunks.length, data);
  }

  ScriptBuilder insertData(int index, Uint8List data) {
    Uint8List copy = Uint8List.fromList(data);
    int opcode;

    if (data.length == 0) {
      opcode = 0;
    } else if (data.length == 1) {
      int b = data[0];
      if (b >= 1 && b <= 16) {
        opcode = SVScript.encodeToOpN(b);
      } else {
        opcode = 1;
      }
    } else if (data.length < 76) {
      opcode = data.length;
    } else if (data.length < 256) {
      opcode = 76;
    } else {
      if (data.length >= 65536) {
        throw new Exception("Unimplemented");
      }

      opcode = 77;
    }

    return this.insertChunk(index, ScriptChunk(copy, copy.length, opcode));
  }

  ScriptBuilder number(int num) {
    return numberAtIndex(_chunks.length, num);
  }

  ScriptBuilder numberAtIndex(int index, int num) {
    if (num == -1) {
      return opCodeAtIndex(index, 79);
    } else {
      return num >= 0 && num <= 16
          ? smallNumAtIndex(index, num)
          : bigNumAtIndex(index, num);
    }
  }

  ScriptBuilder smallNum(int num) {
    return smallNumAtIndex(_chunks.length, num);
  }

  ScriptBuilder bigNum(int num) {
    return bigNumAtIndex(_chunks.length, num);
  }

  ScriptBuilder smallNumAtIndex(int index, int num) {
    PreConditions.assertTrueWithMessage(
        num >= 0, "Cannot encode negative numbers with smallNum");
    PreConditions.assertTrueWithMessage(
        num <= 16, "Cannot encode numbers larger than 16 with smallNum");
    return insertChunk(
        index, ScriptChunk(List.empty(), 0, SVScript.encodeToOpN(num)));
  }

  ScriptBuilder bigNumAtIndex(int index, int num) {
    Uint8List data;
    if (num == 0) {
      data = Uint8List(0);
    } else {
      Queue<int> result = new Queue();
      bool neg = num < 0;

      for (int absvalue = num.abs(); absvalue != 0; absvalue >>= 8) {
        result.add(absvalue & 255);
      }

      if ((result.last & 128) != 0) {
        result.add(neg ? 128 : 0);
      } else if (neg) {
        result.add(result.removeLast() | 128);
      }

      data = Uint8List(result.length);

      var vector = result.toList();
      for (int byteIdx = 0; byteIdx < data.length; ++byteIdx) {
        data[byteIdx] = vector[byteIdx];
      }
    }

    return insertChunk(index, new ScriptChunk(data, data.length, data.length));
  }

  ScriptBuilder opTrue() {
    return number(1);
  }

  ScriptBuilder opTrueAtIndex(int index) {
    return numberAtIndex(index, 1);
  }

  ScriptBuilder opFalse() {
    return number(0);
  }

  ScriptBuilder opFalseAtIndex(int index) {
    return numberAtIndex(index, 0);
  }

  SVScript build() {
    return new SVScript.fromChunks(_chunks);
  }

  static SVScript createEmpty() {
    return (new ScriptBuilder()).build();
  }
}
