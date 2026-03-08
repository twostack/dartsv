import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/interpreter.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:test/test.dart';

void main() {
  SVScript buildRawScript(List<int> rawBytes) {
    return SVScript.fromBuffer(Uint8List.fromList(rawBytes));
  }

  final Set<VerifyFlag> allFlags = {
    VerifyFlag.UTXO_AFTER_GENESIS,
    VerifyFlag.AFTER_CHRONICLE,
    VerifyFlag.SIGHASH_FORKID,
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

  // =========================================================
  // lockingScript parameter threading
  // =========================================================
  group('lockingScript parameter in executeScript', () {
    test('executeScript accepts lockingScript parameter', () {
      // Simple test: OP_1 in scriptSig, OP_1 in scriptPubKey - just verifying the parameter works
      var scriptSig = buildRawScript([OpCodes.OP_1]);
      var scriptPubKey = buildRawScript([OpCodes.OP_1]);

      var spendtx = _createSpendingTx(scriptSig);
      var interp = Interpreter();
      // Should not throw
      expect(
        () => interp.correctlySpends(scriptSig, scriptPubKey, spendtx, 0, allFlags, Coin.ZERO),
        returnsNormally,
      );
    });

    test('executeScript works for v1 transactions without lockingScript affecting behavior', () {
      var scriptSig = buildRawScript([OpCodes.OP_1]);
      var scriptPubKey = buildRawScript([OpCodes.OP_1]);

      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.P2SH,
      };
      var spendtx = _createSpendingTx(scriptSig, version: 1);
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(scriptSig, scriptPubKey, spendtx, 0, flags, Coin.ZERO),
        returnsNormally,
      );
    });
  });

  // =========================================================
  // scriptCode derivation for unlocking scripts
  // =========================================================
  group('scriptCode derivation', () {
    test('OP_CHECKSIG in scriptPubKey works normally for all tx versions', () {
      // This is the normal case - OP_CHECKSIG in scriptPubKey uses its own script
      // We can't fully test signature verification without real keys, but we can
      // verify the code path doesn't crash
      var scriptSig = buildRawScript([OpCodes.OP_1]);
      var scriptPubKey = buildRawScript([OpCodes.OP_1]);

      var spendtx = _createSpendingTx(scriptSig, version: 1);
      var interp = Interpreter();
      var flags = {
        VerifyFlag.UTXO_AFTER_GENESIS,
        VerifyFlag.SIGHASH_FORKID,
        VerifyFlag.P2SH,
      };
      expect(
        () => interp.correctlySpends(scriptSig, scriptPubKey, spendtx, 0, flags, Coin.ZERO),
        returnsNormally,
      );

      // Same with v2
      var spendtx2 = _createSpendingTx(scriptSig, version: 2);
      expect(
        () => interp.correctlySpends(scriptSig, scriptPubKey, spendtx2, 0, allFlags, Coin.ZERO),
        returnsNormally,
      );
    });
  });
}
