import 'dart:convert';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/interpreter.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:test/test.dart';

void main() {
  /// Build a script that pushes data bytes then executes the given opcode(s).
  SVScript buildScript(List<List<int>> dataPushes, List<int> opcodes) {
    var out = ByteDataWriter();
    for (var data in dataPushes) {
      SVScript.writeBytes(out, data);
    }
    for (var op in opcodes) {
      out.writeUint8(op);
    }
    return SVScript.fromBuffer(out.toBytes());
  }

  final Set<VerifyFlag> chronicleFlags = {
    VerifyFlag.UTXO_AFTER_GENESIS,
    VerifyFlag.AFTER_CHRONICLE,
    VerifyFlag.SIGHASH_FORKID,
  };

  final Set<VerifyFlag> preChronicleFlags = {
    VerifyFlag.UTXO_AFTER_GENESIS,
    VerifyFlag.SIGHASH_FORKID,
  };

  /// Create a minimal spending transaction for correctlySpends().
  Transaction _createSpendingTx(SVScript scriptSig, {int version = 2}) {
    var credtx = Transaction();
    credtx.addOutput(TransactionOutput(BigInt.zero, SVScript()));
    credtx.serialize();

    var defaultUnlockBuilder = DefaultUnlockBuilder.fromScript(scriptSig);
    var spendtx = Transaction();
    spendtx.version = version;
    var txSpendInput = TransactionInput(credtx.id, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: defaultUnlockBuilder);
    spendtx.addInput(txSpendInput);
    spendtx.addOutput(TransactionOutput(BigInt.zero, SVScript()));
    return spendtx;
  }

  /// Execute scriptSig + scriptPubkey via correctlySpends. Throws on failure.
  void executeScripts(SVScript scriptSig, SVScript scriptPubkey, Set<VerifyFlag> flags, {int txVersion = 2}) {
    var spendtx = _createSpendingTx(scriptSig, version: txVersion);
    var interp = Interpreter();
    interp.correctlySpends(scriptSig, scriptPubkey, spendtx, 0, flags, Coin.ZERO);
  }

  void expectSuccess(SVScript scriptSig, SVScript scriptPubkey, Set<VerifyFlag> flags, {int txVersion = 2}) {
    expect(() => executeScripts(scriptSig, scriptPubkey, flags, txVersion: txVersion), returnsNormally);
  }

  void expectFailure(SVScript scriptSig, SVScript scriptPubkey, Set<VerifyFlag> flags, {int txVersion = 2}) {
    expect(() => executeScripts(scriptSig, scriptPubkey, flags, txVersion: txVersion), throwsException);
  }

  // =========================================================
  // OP_SUBSTR tests
  // =========================================================
  group('OP_SUBSTR', () {
    test('basic substring extraction', () {
      // "BSV Blockchain" OP_4 OP_5 OP_SUBSTR → "Block"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("BSV Blockchain")],
          [OpCodes.OP_4, OpCodes.OP_5, OpCodes.OP_SUBSTR]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("Block")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('substring from start', () {
      // "Hello" OP_0 OP_3 OP_SUBSTR → "Hel"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("Hello")],
          [OpCodes.OP_0, OpCodes.OP_3, OpCodes.OP_SUBSTR]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("Hel")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('full string extraction', () {
      // "ABC" OP_0 OP_3 OP_SUBSTR → "ABC"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_0, OpCodes.OP_3, OpCodes.OP_SUBSTR]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('error on empty string', () {
      // "" OP_0 OP_0 OP_SUBSTR → error
      var scriptSig = buildScript(
          [],
          [OpCodes.OP_0, OpCodes.OP_0, OpCodes.OP_0, OpCodes.OP_SUBSTR]);
      var scriptPubkey = SVScript();
      expectFailure(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('error when length exceeds string', () {
      // "AB" OP_0 OP_5 OP_SUBSTR → error
      var scriptSig = buildScript(
          [Utf8Encoder().convert("AB")],
          [OpCodes.OP_0, OpCodes.OP_5, OpCodes.OP_SUBSTR]);
      var scriptPubkey = SVScript();
      expectFailure(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('error when start + length exceeds string', () {
      // "Hello" OP_3 OP_5 OP_SUBSTR → error (3+5=8 > 5)
      var scriptSig = buildScript(
          [Utf8Encoder().convert("Hello")],
          [OpCodes.OP_3, OpCodes.OP_5, OpCodes.OP_SUBSTR]);
      var scriptPubkey = SVScript();
      expectFailure(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('treated as NOP pre-Chronicle', () {
      // Pre-Chronicle: OP_SUBSTR (179 = OP_NOP4) should be a NOP
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.one)],
          [OpCodes.OP_SUBSTR]);
      expectSuccess(scriptSig, scriptPubkey, preChronicleFlags);
    });
  });

  // =========================================================
  // OP_LEFT tests
  // =========================================================
  group('OP_LEFT', () {
    test('basic left extraction', () {
      // "BSV Blockchain" OP_3 OP_LEFT → "BSV"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("BSV Blockchain")],
          [OpCodes.OP_3, OpCodes.OP_LEFT]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("BSV")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('zero-length result', () {
      // "Hello" OP_0 OP_LEFT → ""
      var scriptSig = buildScript(
          [Utf8Encoder().convert("Hello")],
          [OpCodes.OP_0, OpCodes.OP_LEFT]);
      var scriptPubkey = buildScript(
          [],
          [OpCodes.OP_0, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('full string', () {
      // "ABC" OP_3 OP_LEFT → "ABC"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_3, OpCodes.OP_LEFT]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('error when length exceeds string', () {
      // "AB" OP_5 OP_LEFT → error
      var scriptSig = buildScript(
          [Utf8Encoder().convert("AB")],
          [OpCodes.OP_5, OpCodes.OP_LEFT]);
      var scriptPubkey = SVScript();
      expectFailure(scriptSig, scriptPubkey, chronicleFlags);
    });
  });

  // =========================================================
  // OP_RIGHT tests
  // =========================================================
  group('OP_RIGHT', () {
    test('basic right extraction', () {
      // "BSV Blockchain" OP_5 OP_RIGHT → "chain"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("BSV Blockchain")],
          [OpCodes.OP_5, OpCodes.OP_RIGHT]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("chain")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('zero-length result', () {
      // "Hello" OP_0 OP_RIGHT → ""
      var scriptSig = buildScript(
          [Utf8Encoder().convert("Hello")],
          [OpCodes.OP_0, OpCodes.OP_RIGHT]);
      var scriptPubkey = buildScript(
          [],
          [OpCodes.OP_0, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('full string', () {
      // "ABC" OP_3 OP_RIGHT → "ABC"
      var scriptSig = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_3, OpCodes.OP_RIGHT]);
      var scriptPubkey = buildScript(
          [Utf8Encoder().convert("ABC")],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('error when length exceeds string', () {
      // "AB" OP_5 OP_RIGHT → error
      var scriptSig = buildScript(
          [Utf8Encoder().convert("AB")],
          [OpCodes.OP_5, OpCodes.OP_RIGHT]);
      var scriptPubkey = SVScript();
      expectFailure(scriptSig, scriptPubkey, chronicleFlags);
    });
  });

  // =========================================================
  // OP_2MUL tests
  // =========================================================
  group('OP_2MUL', () {
    test('positive number', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(5))],
          [OpCodes.OP_2MUL, OpCodes.OP_10, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('negative number', () {
      var scriptSig = buildScript(
          [castToBuffer(BigInt.from(-3))],
          [OpCodes.OP_2MUL]);
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(-6))],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('zero', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [],
          [OpCodes.OP_0, OpCodes.OP_2MUL, OpCodes.OP_0, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('disabled pre-Chronicle', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(5))],
          [OpCodes.OP_2MUL]);
      expectFailure(scriptSig, scriptPubkey, preChronicleFlags);
    });
  });

  // =========================================================
  // OP_2DIV tests
  // =========================================================
  group('OP_2DIV', () {
    test('even number', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(10))],
          [OpCodes.OP_2DIV, OpCodes.OP_5, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('odd number truncates', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(7))],
          [OpCodes.OP_2DIV, OpCodes.OP_3, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('negative number', () {
      var scriptSig = buildScript(
          [castToBuffer(BigInt.from(-6))],
          [OpCodes.OP_2DIV]);
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(-3))],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('zero', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [],
          [OpCodes.OP_0, OpCodes.OP_2DIV, OpCodes.OP_0, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('disabled pre-Chronicle', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(10))],
          [OpCodes.OP_2DIV]);
      expectFailure(scriptSig, scriptPubkey, preChronicleFlags);
    });
  });

  // =========================================================
  // OP_LSHIFTNUM tests
  // =========================================================
  group('OP_LSHIFTNUM', () {
    test('basic left shift', () {
      // 1 << 3 = 8
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.one)],
          [OpCodes.OP_3, OpCodes.OP_LSHIFTNUM, OpCodes.OP_8, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('shift by zero', () {
      // 5 << 0 = 5
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(5))],
          [OpCodes.OP_0, OpCodes.OP_LSHIFTNUM, OpCodes.OP_5, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('preserves sign (negative)', () {
      // -1 << 2 = -4
      var scriptSig = buildScript(
          [castToBuffer(BigInt.from(-1))],
          [OpCodes.OP_2, OpCodes.OP_LSHIFTNUM]);
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(-4))],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('treated as NOP pre-Chronicle', () {
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.one)],
          [OpCodes.OP_LSHIFTNUM]);
      expectSuccess(scriptSig, scriptPubkey, preChronicleFlags);
    });
  });

  // =========================================================
  // OP_RSHIFTNUM tests
  // =========================================================
  group('OP_RSHIFTNUM', () {
    test('basic right shift', () {
      // 8 >> 2 = 2
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(8))],
          [OpCodes.OP_2, OpCodes.OP_RSHIFTNUM, OpCodes.OP_2, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('shift by zero', () {
      // 5 >> 0 = 5
      var scriptSig = SVScript();
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(5))],
          [OpCodes.OP_0, OpCodes.OP_RSHIFTNUM, OpCodes.OP_5, OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });

    test('preserves sign (negative)', () {
      // -8 >> 1 = -4
      var scriptSig = buildScript(
          [castToBuffer(BigInt.from(-8))],
          [OpCodes.OP_1, OpCodes.OP_RSHIFTNUM]);
      var scriptPubkey = buildScript(
          [castToBuffer(BigInt.from(-4))],
          [OpCodes.OP_EQUAL]);
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags);
    });
  });

  // =========================================================
  // OP_VER tests
  // =========================================================
  group('OP_VER', () {
    test('pushes transaction version onto stack', () {
      // OP_VER should push 2, then compare with OP_2
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_VER);
      out.writeUint8(OpCodes.OP_2);
      out.writeUint8(OpCodes.OP_EQUAL);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 2);
    });

    test('version 1 transaction', () {
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_VER);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_EQUAL);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 1);
    });

    test('throws pre-Chronicle', () {
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_VER);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectFailure(scriptSig, scriptPubkey, preChronicleFlags, txVersion: 2);
    });
  });

  // =========================================================
  // OP_VERIF / OP_VERNOTIF tests
  // =========================================================
  group('OP_VERIF', () {
    test('branches when version >= comparison value', () {
      // Push 2 (comparison), OP_VERIF (version(2) >= 2 → true), OP_1 ELSE OP_0 ENDIF
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_2);
      out.writeUint8(OpCodes.OP_VERIF);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_ELSE);
      out.writeUint8(OpCodes.OP_0);
      out.writeUint8(OpCodes.OP_ENDIF);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 2);
    });

    test('does not branch when version < comparison value', () {
      // Push 2, OP_VERIF (version(1) >= 2 → false), OP_0 ELSE OP_1 ENDIF
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_2);
      out.writeUint8(OpCodes.OP_VERIF);
      out.writeUint8(OpCodes.OP_0);
      out.writeUint8(OpCodes.OP_ELSE);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_ENDIF);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 1);
    });

    test('throws pre-Chronicle', () {
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_VERIF);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_ENDIF);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectFailure(scriptSig, scriptPubkey, preChronicleFlags, txVersion: 2);
    });
  });

  group('OP_VERNOTIF', () {
    test('branches when version < comparison value (inverted)', () {
      // Push 2, OP_VERNOTIF (version(1) >= 2 → false → NOT → true)
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_2);
      out.writeUint8(OpCodes.OP_VERNOTIF);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_ELSE);
      out.writeUint8(OpCodes.OP_0);
      out.writeUint8(OpCodes.OP_ENDIF);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 1);
    });

    test('does not branch when version >= comparison value', () {
      // Push 2, OP_VERNOTIF (version(2) >= 2 → true → NOT → false)
      var out = ByteDataWriter();
      out.writeUint8(OpCodes.OP_2);
      out.writeUint8(OpCodes.OP_VERNOTIF);
      out.writeUint8(OpCodes.OP_0);
      out.writeUint8(OpCodes.OP_ELSE);
      out.writeUint8(OpCodes.OP_1);
      out.writeUint8(OpCodes.OP_ENDIF);
      var scriptPubkey = SVScript.fromBuffer(out.toBytes());
      var scriptSig = SVScript();
      expectSuccess(scriptSig, scriptPubkey, chronicleFlags, txVersion: 2);
    });
  });
}
