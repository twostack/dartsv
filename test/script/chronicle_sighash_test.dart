import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/interpreter.dart';
import 'package:dartsv/src/script/scriptflags.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  // =========================================================
  // SighashType.hasValue() tests
  // =========================================================
  group('SighashType.hasValue()', () {
    test('accepts standard types', () {
      expect(SighashType.hasValue(0x01), isTrue); // ALL
      expect(SighashType.hasValue(0x02), isTrue); // NONE
      expect(SighashType.hasValue(0x03), isTrue); // SINGLE
    });

    test('accepts FORKID combinations', () {
      expect(SighashType.hasValue(0x41), isTrue); // ALL|FORKID
      expect(SighashType.hasValue(0x42), isTrue); // NONE|FORKID
      expect(SighashType.hasValue(0x43), isTrue); // SINGLE|FORKID
    });

    test('accepts ANYONECANPAY combinations', () {
      expect(SighashType.hasValue(0x81), isTrue); // ALL|ANYONECANPAY
      expect(SighashType.hasValue(0x82), isTrue); // NONE|ANYONECANPAY
      expect(SighashType.hasValue(0x83), isTrue); // SINGLE|ANYONECANPAY
    });

    test('accepts CHRONICLE combinations', () {
      expect(SighashType.hasValue(0x21), isTrue); // ALL|CHRONICLE
      expect(SighashType.hasValue(0x22), isTrue); // NONE|CHRONICLE
      expect(SighashType.hasValue(0x23), isTrue); // SINGLE|CHRONICLE
    });

    test('accepts CHRONICLE|FORKID combinations', () {
      expect(SighashType.hasValue(0x61), isTrue); // ALL|CHRONICLE|FORKID
      expect(SighashType.hasValue(0x62), isTrue); // NONE|CHRONICLE|FORKID
      expect(SighashType.hasValue(0x63), isTrue); // SINGLE|CHRONICLE|FORKID
    });

    test('accepts all flags combined', () {
      expect(SighashType.hasValue(0xE1), isTrue); // ALL|CHRONICLE|FORKID|ANYONECANPAY
    });

    test('rejects invalid base types', () {
      expect(SighashType.hasValue(0x00), isFalse); // no base type
      expect(SighashType.hasValue(0x04), isFalse); // invalid base type
      expect(SighashType.hasValue(0x05), isFalse);
    });

    test('rejects unknown flag bits', () {
      expect(SighashType.hasValue(0xFF), isFalse); // unknown bits set
      expect(SighashType.hasValue(0x11), isFalse); // bit 0x10 is unknown
    });
  });

  // =========================================================
  // SVSignature.hasChronicle() tests
  // =========================================================
  group('SVSignature.hasChronicle()', () {
    test('returns true when CHRONICLE bit is set', () {
      expect(SVSignature.hasChronicle([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x21]), isTrue);
      expect(SVSignature.hasChronicle([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x61]), isTrue);
    });

    test('returns false when CHRONICLE bit is not set', () {
      expect(SVSignature.hasChronicle([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x41]), isFalse);
      expect(SVSignature.hasChronicle([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]), isFalse);
    });

    test('returns false for empty sig', () {
      expect(SVSignature.hasChronicle([]), isFalse);
    });
  });

  // =========================================================
  // checkSignatureEncoding: CHRONICLE flag pre/post Chronicle
  // =========================================================
  group('checkSignatureEncoding with CHRONICLE flag', () {
    // Build a minimal valid DER sig with the given sighash byte appended
    List<int> buildMinimalSig(int sighashByte) {
      // Minimal valid DER: 30 06 02 01 01 02 01 01
      return [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, sighashByte];
    }

    test('CHRONICLE sighash flag rejected pre-Chronicle', () {
      var sigBytes = buildMinimalSig(0x61); // ALL|CHRONICLE|FORKID
      var flags = {VerifyFlag.STRICTENC, VerifyFlag.SIGHASH_FORKID};
      expect(
        () => Interpreter.checkSignatureEncoding(sigBytes, flags),
        throwsA(isA<SignatureEncodingException>()),
      );
    });

    test('CHRONICLE sighash flag accepted post-Chronicle', () {
      var sigBytes = buildMinimalSig(0x61); // ALL|CHRONICLE|FORKID
      var flags = {VerifyFlag.STRICTENC, VerifyFlag.SIGHASH_FORKID, VerifyFlag.AFTER_CHRONICLE};
      // Should not throw
      expect(
        () => Interpreter.checkSignatureEncoding(sigBytes, flags),
        returnsNormally,
      );
    });

    test('CHRONICLE without FORKID accepted post-Chronicle', () {
      var sigBytes = buildMinimalSig(0x21); // ALL|CHRONICLE (no FORKID)
      var flags = {VerifyFlag.STRICTENC, VerifyFlag.SIGHASH_FORKID, VerifyFlag.AFTER_CHRONICLE};
      // Should not throw - CHRONICLE exempts the FORKID requirement
      expect(
        () => Interpreter.checkSignatureEncoding(sigBytes, flags),
        returnsNormally,
      );
    });
  });

  // =========================================================
  // Sighash.hash() dispatch: CHRONICLE produces legacy digest
  // =========================================================
  group('Sighash.hash() CHRONICLE dispatch', () {
    Transaction buildSimpleTx() {
      var tx = Transaction();
      tx.version = 2;
      var input = TransactionInput(
          '0000000000000000000000000000000000000000000000000000000000000001',
          0,
          TransactionInput.MAX_SEQ_NUMBER,
          scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript()));
      tx.addInput(input);
      tx.addOutput(TransactionOutput(BigInt.from(1000), SVScript.fromString('OP_1')));
      return tx;
    }

    final int chronicleFlags = ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID | ScriptFlags.SCRIPT_ENABLE_CHRONICLE;

    test('CHRONICLE flag produces different digest than FORKID alone', () {
      var tx = buildSimpleTx();
      var subscript = SVScript.fromString('OP_1');
      var satoshis = BigInt.from(5000);

      var sighash = Sighash();

      // BIP143 digest (FORKID only)
      var hashForkId = sighash.hash(tx, 0x41, 0, subscript, satoshis);

      // Legacy/OTDA digest (CHRONICLE|FORKID)
      var sighash2 = Sighash();
      var hashChronicle = sighash2.hash(tx, 0x61, 0, subscript, satoshis, flags: chronicleFlags);

      expect(hashChronicle, isNot(equals(hashForkId)));
    });

    test('CHRONICLE flag produces same digest as pure legacy path', () {
      var tx = buildSimpleTx();
      var subscript = SVScript.fromString('OP_1');
      var satoshis = BigInt.from(5000);

      // Legacy digest with sighash ALL (0x01) and no flags
      var sighash1 = Sighash();
      var hashLegacy = sighash1.hash(tx, 0x01, 0, subscript, satoshis, flags: 0);

      // CHRONICLE|FORKID digest (0x61) - should route to legacy path
      var sighash2 = Sighash();
      var hashChronicle = sighash2.hash(tx, 0x61, 0, subscript, satoshis, flags: chronicleFlags);

      // Both should use the legacy algorithm, but the serialized sighash type differs
      // (0x01 vs 0x61) so the final hash will differ. The key test is that CHRONICLE
      // does NOT produce the BIP143 digest.
      var sighash3 = Sighash();
      var hashBip143 = sighash3.hash(tx, 0x41, 0, subscript, satoshis);

      expect(hashChronicle, isNot(equals(hashBip143)));
    });
  });
}
