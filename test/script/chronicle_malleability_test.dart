import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/interpreter.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:test/test.dart';

void main() {
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

  /// Build a raw script from raw bytes (no automatic push encoding).
  SVScript buildRawScript(List<int> rawBytes) {
    return SVScript.fromBuffer(Uint8List.fromList(rawBytes));
  }

  final Set<VerifyFlag> allFlags = {
    VerifyFlag.UTXO_AFTER_GENESIS,
    VerifyFlag.AFTER_CHRONICLE,
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.SIGPUSHONLY,
    VerifyFlag.CLEANSTACK,
    VerifyFlag.MINIMALDATA,
    VerifyFlag.MINIMALIF,
    VerifyFlag.P2SH,
  };

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
  // SIGPUSHONLY relaxation
  // =========================================================
  group('SIGPUSHONLY relaxation', () {
    test('scriptSig with non-push opcode passes with tx version 2', () {
      // scriptSig: OP_1 OP_DROP OP_1 (contains non-push OP_DROP)
      var scriptSig = buildRawScript([OpCodes.OP_1, OpCodes.OP_DROP, OpCodes.OP_1]);
      // scriptPubkey: OP_1 (just needs stack to have true on top)
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      expectSuccess(scriptSig, scriptPubkey, allFlags, txVersion: 2);
    });

    test('scriptSig with non-push opcode fails with tx version 1', () {
      var scriptSig = buildRawScript([OpCodes.OP_1, OpCodes.OP_DROP, OpCodes.OP_1]);
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      expectFailure(scriptSig, scriptPubkey, allFlags, txVersion: 1);
    });
  });

  // =========================================================
  // CLEANSTACK relaxation
  // =========================================================
  group('CLEANSTACK relaxation', () {
    test('extra items on stack passes with tx version 2', () {
      // scriptSig pushes two OP_1 values; scriptPubkey is OP_1 (pushes true)
      // Stack will have: [1, 1, 1] — not clean but should pass with v2
      var scriptSig = buildRawScript([OpCodes.OP_1, OpCodes.OP_1]);
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      expectSuccess(scriptSig, scriptPubkey, allFlags, txVersion: 2);
    });

    test('extra items on stack fails with tx version 1', () {
      var scriptSig = buildRawScript([OpCodes.OP_1, OpCodes.OP_1]);
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      expectFailure(scriptSig, scriptPubkey, allFlags, txVersion: 1);
    });
  });

  // =========================================================
  // MINIMALDATA relaxation
  // =========================================================
  group('MINIMALDATA relaxation', () {
    test('non-minimal push passes with tx version 2', () {
      // Use PUSHDATA1 to push a single byte [0x01] — non-minimal since OP_1 should be used
      // scriptSig: PUSHDATA1 0x01 0x01 (non-minimal push of 1)
      var scriptSig = buildRawScript([OpCodes.OP_PUSHDATA1, 0x01, 0x01]);
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.MINIMALDATA,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('non-minimal push fails with tx version 1', () {
      var scriptSig = buildRawScript([OpCodes.OP_PUSHDATA1, 0x01, 0x01]);
      var scriptPubkey = buildRawScript([OpCodes.OP_1]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.MINIMALDATA,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });

  // =========================================================
  // MINIMALIF relaxation
  // =========================================================
  group('MINIMALIF relaxation', () {
    test('OP_IF with non-minimal argument passes with tx version 2', () {
      // scriptSig pushes [0x02] (non-minimal true for OP_IF — not 0x00 or 0x01)
      // scriptPubkey: OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
      var scriptSig = buildScript([[0x02]], []);
      var scriptPubkey = buildRawScript([
        OpCodes.OP_IF, OpCodes.OP_1, OpCodes.OP_ELSE, OpCodes.OP_0, OpCodes.OP_ENDIF
      ]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.MINIMALIF,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('OP_IF with non-minimal argument fails with tx version 1', () {
      var scriptSig = buildScript([[0x02]], []);
      var scriptPubkey = buildRawScript([
        OpCodes.OP_IF, OpCodes.OP_1, OpCodes.OP_ELSE, OpCodes.OP_0, OpCodes.OP_ENDIF
      ]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.MINIMALIF,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });

  // =========================================================
  // LOW_S relaxation
  // =========================================================

  // secp256k1 generator point G (compressed) — a valid public key
  final List<int> testPubKey = [
    0x02,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
  ];

  /// Craft a DER signature with high S (S = 2^255, which is > n/2).
  /// Format: 30 <len> 02 01 01 02 21 00 80 00..00 <sighash>
  /// R = 1, S = 0x00 80 00..00 (33 DER bytes = positive 2^255)
  List<int> craftHighSSignature() {
    var sig = <int>[
      0x30, 0x26,       // SEQUENCE, total inner length = 38
      0x02, 0x01, 0x01, // INTEGER, R = 1
      0x02, 0x21,       // INTEGER, S length = 33
      0x00, 0x80,       // S padding byte + high byte
    ];
    sig.addAll(List.filled(31, 0x00)); // remaining 31 zero bytes of S
    sig.add(0x41);                     // SIGHASH_ALL | SIGHASH_FORKID
    return sig;
  }

  /// Craft a minimal valid DER signature with low S (R=1, S=1).
  /// Format: 30 06 02 01 01 02 01 01 <sighash>
  List<int> craftLowSFakeSignature() {
    return [
      0x30, 0x06,       // SEQUENCE, total inner length = 6
      0x02, 0x01, 0x01, // INTEGER, R = 1
      0x02, 0x01, 0x01, // INTEGER, S = 1
      0x41,             // SIGHASH_ALL | SIGHASH_FORKID
    ];
  }

  group('LOW_S relaxation', () {
    test('high-S signature passes with tx version 2', () {
      // scriptSig: push high-S signature
      // scriptPubkey: <pubkey> OP_CHECKSIG OP_NOT
      // Verification fails (fake sig) → pushes false → OP_NOT → true
      // With v2, LOW_S check is skipped so checkSignatureEncoding passes
      var scriptSig = buildScript([craftHighSSignature()], []);
      var scriptPubkey = buildScript([testPubKey], [OpCodes.OP_CHECKSIG, OpCodes.OP_NOT]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.LOW_S,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('high-S signature fails with tx version 1', () {
      var scriptSig = buildScript([craftHighSSignature()], []);
      var scriptPubkey = buildScript([testPubKey], [OpCodes.OP_CHECKSIG, OpCodes.OP_NOT]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.LOW_S,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });

  // =========================================================
  // NULLFAIL relaxation (CHECKSIG)
  // =========================================================
  group('NULLFAIL relaxation (CHECKSIG)', () {
    test('non-empty failed signature passes with tx version 2', () {
      // scriptSig: push a valid-DER but wrong signature (low S, won't verify)
      // scriptPubkey: <pubkey> OP_CHECKSIG OP_NOT
      // CHECKSIG fails → with v2 NULLFAIL is skipped → pushes false → OP_NOT → true
      var scriptSig = buildScript([craftLowSFakeSignature()], []);
      var scriptPubkey = buildScript([testPubKey], [OpCodes.OP_CHECKSIG, OpCodes.OP_NOT]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLFAIL,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('non-empty failed signature fails with tx version 1', () {
      var scriptSig = buildScript([craftLowSFakeSignature()], []);
      var scriptPubkey = buildScript([testPubKey], [OpCodes.OP_CHECKSIG, OpCodes.OP_NOT]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLFAIL,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });

  // =========================================================
  // NULLFAIL relaxation (CHECKMULTISIG)
  // =========================================================
  group('NULLFAIL relaxation (CHECKMULTISIG)', () {
    test('non-empty failed signature in multisig passes with tx version 2', () {
      // 1-of-1 multisig with a fake signature that won't verify.
      // scriptSig: OP_0 (dummy) <fake_sig>
      // scriptPubkey: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG OP_NOT
      var sigSigOut = ByteDataWriter();
      sigSigOut.writeUint8(OpCodes.OP_0); // empty dummy
      SVScript.writeBytes(sigSigOut, craftLowSFakeSignature());
      var scriptSig = SVScript.fromBuffer(sigSigOut.toBytes());

      var pubKeyOut = ByteDataWriter();
      pubKeyOut.writeUint8(OpCodes.OP_1);
      SVScript.writeBytes(pubKeyOut, testPubKey);
      pubKeyOut.writeUint8(OpCodes.OP_1);
      pubKeyOut.writeUint8(OpCodes.OP_CHECKMULTISIG);
      pubKeyOut.writeUint8(OpCodes.OP_NOT);
      var scriptPubkey = SVScript.fromBuffer(pubKeyOut.toBytes());

      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLFAIL,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('non-empty failed signature in multisig fails with tx version 1', () {
      var sigSigOut = ByteDataWriter();
      sigSigOut.writeUint8(OpCodes.OP_0);
      SVScript.writeBytes(sigSigOut, craftLowSFakeSignature());
      var scriptSig = SVScript.fromBuffer(sigSigOut.toBytes());

      var pubKeyOut = ByteDataWriter();
      pubKeyOut.writeUint8(OpCodes.OP_1);
      SVScript.writeBytes(pubKeyOut, testPubKey);
      pubKeyOut.writeUint8(OpCodes.OP_1);
      pubKeyOut.writeUint8(OpCodes.OP_CHECKMULTISIG);
      pubKeyOut.writeUint8(OpCodes.OP_NOT);
      var scriptPubkey = SVScript.fromBuffer(pubKeyOut.toBytes());

      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLFAIL,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });

  // =========================================================
  // NULLDUMMY relaxation
  // =========================================================
  group('NULLDUMMY relaxation', () {
    test('non-empty dummy in CHECKMULTISIG passes with tx version 2', () {
      // We test this at the executeMultiSig level via executeScript directly.
      // scriptSig: push [0x01] (non-empty dummy), then 0 sigs
      // scriptPubkey: OP_0 OP_0 OP_CHECKMULTISIG
      // This creates a 0-of-0 multisig that always succeeds,
      // but the dummy element [0x01] is non-empty, which NULLDUMMY normally rejects.
      var scriptSig = buildScript([[0x01]], []);
      var scriptPubkey = buildRawScript([
        OpCodes.OP_0, OpCodes.OP_0, OpCodes.OP_CHECKMULTISIG
      ]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLDUMMY,
      };
      expectSuccess(scriptSig, scriptPubkey, flags, txVersion: 2);
    });

    test('non-empty dummy in CHECKMULTISIG fails with tx version 1', () {
      var scriptSig = buildScript([[0x01]], []);
      var scriptPubkey = buildRawScript([
        OpCodes.OP_0, OpCodes.OP_0, OpCodes.OP_CHECKMULTISIG
      ]);
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.AFTER_CHRONICLE,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.NULLDUMMY,
      };
      expectFailure(scriptSig, scriptPubkey, flags, txVersion: 1);
    });
  });
}
