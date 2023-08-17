import 'dart:convert';
import 'dart:io';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/interpreter_v2.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/scriptflags.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  SVScript parseScriptString(String string) {
    List<String> words = string.split(" ");

    var out = ByteDataWriter();

    for (String w in words) {
      if (w == "") continue;
      if (RegExp(r"^-?[0-9]*$").hasMatch(w)) {
        // Number
        int val = int.parse(w);
        if (val >= -1 && val <= 16) {
          out.writeUint8(SVScript.encodeToOpN(val));
        } else {
          SVScript.writeBytes(out, castToBuffer(BigInt.from(val)));
        }
      } else if (RegExp(r"^0x[0-9a-fA-F]*$").hasMatch(w)) {
        // Raw hex data, inserted NOT pushed onto stack:
        out.write(HEX.decode(w.substring(2).toLowerCase()));
      } else if (w.length >= 2 && w.startsWith("'") && w.endsWith("'")) {
        // Single-quoted string, pushed as data. NOTE: this is poor-man's
        // parsing, spaces/tabs/newlines in single-quoted strings won't work.
        SVScript.writeBytes(out, Utf8Encoder().convert(w.substring(1, w.length - 1)));
      } else if (OpCodes.getOpCode("OP_${w}") != OpCodes.OP_INVALIDOPCODE) {
        // opcode, e.g. OP_ADD or OP_1:
        out.writeUint8(OpCodes.getOpCode("OP_${w}"));
      } else if (w.startsWith("OP_") && OpCodes.getOpCode(w.substring(3)) != OpCodes.OP_INVALIDOPCODE) {
        // opcode, e.g. OP_ADD or OP_1:
        out.writeUint8(OpCodes.getOpCode(w.substring(3)));
      } else {
        throw Exception("Invalid word: '" + w + "'");
      }
    }

    return SVScript.fromBuffer(out.toBytes());
  }

  Set<VerifyFlag> parseVerifyFlags(dynamic flagVar) {

    var flagStr;
    if (flagVar is String){
      flagStr = flagVar;
    }else if (flagVar is List){
      flagStr = flagVar.fold("", (previousValue, element) => "${previousValue},${element}");
    }

    Set<VerifyFlag> flags = Set.identity();
    if (!("NONE" == flagStr)) {
      for (String flag in flagStr.split(",")) {
        try {
          var flagToAdd = VerifyFlag.values
              .where((element) => element.toString() == "VerifyFlag.${flag}")
              .firstOrNull;
          if (flagToAdd != null) flags.add(flagToAdd);
          // flags.add(VerifyFlag.valueOf(flag));
        } on IllegalArgumentException catch (x) {
          print("Cannot handle verify flag {} -- ignored.");
        }
      }
    }
    return flags;
  }

  getFlags(flagstr) {
    var flags = 0;
    if (flagstr.indexOf('NONE') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_NONE;
    }
    if (flagstr.indexOf('P2SH') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_P2SH;
    }
    if (flagstr.indexOf('STRICTENC') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_STRICTENC;
    }
    if (flagstr.indexOf('DERSIG') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_DERSIG;
    }
    if (flagstr.indexOf('LOW_S') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_LOW_S;
    }
    if (flagstr.indexOf('NULLDUMMY') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_NULLDUMMY;
    }
    if (flagstr.indexOf('SIGPUSHONLY') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY;
    }
    if (flagstr.indexOf('MINIMALDATA') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_MINIMALDATA;
    }
    if (flagstr.indexOf('DISCOURAGE_UPGRADABLE_NOPS') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    }
    if (flagstr.indexOf('CHECKLOCKTIMEVERIFY') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if (flagstr.indexOf('CHECKSEQUENCEVERIFY') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }
    if (flagstr.indexOf('NULLFAIL') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_NULLFAIL;
    }

    if (flagstr.indexOf('CLEANSTACK') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_CLEANSTACK;
    }

    if (flagstr.indexOf('FORKID') != -1) {
      flags = flags | ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID;
    }

    if (flagstr.indexOf('REPLAY_PROTECTION') != -1) {
      flags = flags | ScriptFlags.SCRIPT_ENABLE_REPLAY_PROTECTION;
    }

    if (flagstr.indexOf('MONOLITH') != -1) {
      flags = flags | ScriptFlags.SCRIPT_ENABLE_MONOLITH_OPCODES;
    }

    if (flagstr.indexOf('UTXO_AFTER_GENESIS') != -1) {
      flags = flags | ScriptFlags.SCRIPT_UTXO_AFTER_GENESIS;
    }

    if (flagstr.indexOf('MINIMALIF') != -1) {
      flags = flags | ScriptFlags.SCRIPT_VERIFY_MINIMALIF;
    }
    return flags;
  }

  group('Interpreter API', () {
    test('should make a new interpreter', () {
      var interp = new Interpreter();
      expect(interp.stack.length, equals(0));
      expect(interp.altStack.length, equals(0));
      expect(interp.pc, equals(0));
      expect(interp.pbegincodehash, equals(0));
      expect(interp.nOpCount, equals(0));
      expect(interp.vfExec.length, equals(0));
      expect(interp.errstr, equals(''));
      expect(interp.flags, equals(0));
    });

    test('interpreter can set new values for stacks', () {
      var interp = new Interpreter();
      interp.stack.push([1, 2, 3]);
      expect(interp.stack.length, equals(1));
      interp.altStack.push([4, 5, 6]);
      expect(interp.altStack.length, equals(1));
      interp.clearStacks();
      expect(interp.stack.length, equals(0));
      expect(interp.altStack.length, equals(0));
    });
  });

  group('Script Verification', () {
    test('should verify these trivial scripts', () {
      bool verified;
      var si = Interpreter();
      verified = si.verifyScript(SVScript.fromString('OP_1'), SVScript.fromString('OP_1'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_1'), SVScript.fromString('OP_0'));
      expect(verified, isFalse);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_0'), SVScript.fromString('OP_1'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_CODESEPARATOR'), SVScript.fromString('OP_1'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString(''), SVScript.fromString('OP_DEPTH OP_0 OP_EQUAL'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_1 OP_2'), SVScript.fromString('OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('9 0x000000000000000010'), SVScript.fromString(''));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_1'), SVScript.fromString('OP_15 OP_ADD OP_16 OP_EQUAL'));
      expect(verified, isTrue);
      verified = Interpreter().verifyScript(SVScript.fromString('OP_0'), SVScript.fromString('OP_IF OP_VER OP_ELSE OP_1 OP_ENDIF'));
      expect(verified, isTrue);
    });

    /* FIXME: This test is likely broken since test vectors are passing
        test('should verify these simple transaction', () {
            // first we create a transaction
            var privateKey = new SVPrivateKey.fromWIF('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
            var publicKey = privateKey.publicKey;
            var fromAddress = publicKey.toAddress(NetworkType.TEST);
            var toAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
            var scriptPubkey = P2PKHLockBuilder.fromAddress(fromAddress).getScriptPubkey();
            var utxo = {
                "address": fromAddress,
                "transactionId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
                "outputIndex": 0,
                'sequenceNumber': TransactionInput.MAX_SEQ_NUMBER,
                "scriptPubKey": scriptPubkey.toString(),
                "satoshis": 100000
            };
            var scriptSigBuilder = P2PKHUnlockBuilder(publicKey);
            var signer = TransactionSigner(1, privateKey);
            var txBuilder = TransactionBuilder()
                .spendFromUtxoMapWithSigner(signer, utxo, scriptSigBuilder )
                .spendToLockBuilder(P2PKHLockBuilder.fromAddress(toAddress), BigInt.from(100000));

            var tx = txBuilder.build(false);

            // we then extract the signature from the first input
            var inputIndex = 0;
            // print(HEX.encode(hash160(HEX.decode(publicKey.toString()))));

            var scriptSig = scriptSigBuilder.getScriptSig();

            var flags = ScriptFlags.SCRIPT_VERIFY_P2SH | ScriptFlags.SCRIPT_VERIFY_STRICTENC;
            var interpreter = Interpreter();

            var verified = interpreter.verifyScript(
                scriptSig,
                scriptPubkey,
                tx: tx,
                nin: inputIndex,
                flags: flags,
                satoshis: BigInt.from(utxo["satoshis"] as int) );

            expect(interpreter.errstr, equals(""));
            expect(verified, isTrue);
        });

         */
  });

  group('@castToBool', () {
    test('should cast these bufs to bool correctly', () {
      expect(Interpreter().castBigIntToBool(BigInt.zero), equals(false));

      expect(Interpreter().castToBool(HEX.decode(BigInt.zero.toRadixString(16))), equals(false));
      expect(Interpreter().castToBool(HEX.decode('0080')), equals(false)); // negative 0
      expect(Interpreter().castToBool(HEX.decode(BigInt.one.toRadixString(16))), equals(true));

      //FIXME: What do we do about lack of sign-magnitude representation in Dart ?
//      expect(Interpreter().castToBool(HEX.decode(BigInt.from(-1).toRadixString(16))), equals(true));
      /*
      var buf = Buffer.from('00', 'hex')
      var bool = BN.fromSM(buf, {
        endian: 'little'
      }).cmp(BN.Zero) !== 0
      ScriptFlags.castToBool(buf).should.equal(bool)
       */
    });
  });

  var toBitpattern = (String binaryString) {
    return int.parse(binaryString, radix: 2).toRadixString(16).padLeft(8, '0');
  };

  var evaluateScript = (List<int> arraySig, List<int> arrayPubKey, int op) {
    var flags = ScriptFlags.SCRIPT_VERIFY_P2SH | ScriptFlags.SCRIPT_UTXO_AFTER_GENESIS | ScriptFlags.SCRIPT_ENABLE_MONOLITH_OPCODES;
    Interpreter interp = Interpreter.fromScript(SVScript().add(arraySig).add(arrayPubKey), flags);
    interp.script.add(op);
    interp.evaluate();
    return interp;
  };

  group('#OP_LSHIFT tests from bitcoind', () {
    test('should not shift when no n value', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('10011111000100011111010101010101');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 1', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x01], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('00111110001000111110101010101010');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 2', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x02], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('01111100010001111101010101010100');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 3', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x03], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('11111000100011111010101010101000');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 4', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x04], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('11110001000111110101010101010000');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 5', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x05], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('11100010001111101010101010100000')));
    });

    test('should shift left 6', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x06], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('11000100011111010101010101000000')));
    });

    test('should shift left 7', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x07], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('10001000111110101010101010000000')));
    });

    test('should shift left 8', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x08], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00010001111101010101010100000000')));
    });

    test('should shift left 9', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x09], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      var bitPattern = toBitpattern('00100011111010101010101000000000');
      expect(HEX.encode(result), equals(bitPattern));
    });

    test('should shift left 0A', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0A], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('01000111110101010101010000000000')));
    });

    test('should shift left 0B', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0B], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('10001111101010101010100000000000')));
    });

    test('should shift left 0C', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0C], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00011111010101010101000000000000')));
    });

    test('should shift left 0D', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0D], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00111110101010101010000000000000')));
    });

    test('should shift left 0E', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0E], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('01111101010101010100000000000000')));
    });

    test('should shift left 0F', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0F], OpCodes.OP_LSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('11111010101010101000000000000000')));
    });
  });

  group('#OP_RSHIFT tests from bitcoind', () {
    test('should not shift when no n value', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('10011111000100011111010101010101')));
    });

    test('should shift right 1', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x01], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('01001111100010001111101010101010')));
    });

    test('should shift right 2', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x02], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00100111110001000111110101010101')));
    });

    test('should shift right 3', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x03], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00010011111000100011111010101010')));
    });

    test('should shift right 4', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x04], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00001001111100010001111101010101')));
    });

    test('should shift right 5', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x05], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000100111110001000111110101010')));
    });

    test('should shift right 6', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x06], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000010011111000100011111010101')));
    });

    test('should shift right 7', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x07], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000001001111100010001111101010')));
    });

    test('should shift right 08', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x08], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000100111110001000111110101')));
    });

    test('should shift right 9', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x09], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000010011111000100011111010')));
    });

    test('should shift right 0A', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0A], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000001001111100010001111101')));
    });

    test('should shift right 0B', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0B], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000000100111110001000111110')));
    });

    test('should shift right 0C', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0C], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000000010011111000100011111')));
    });

    test('should shift right 0D', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0D], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000000001001111100010001111')));
    });

    test('should shift right 0E', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0E], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000000000100111110001000111')));
    });

    test('should shift right 0F', () {
      var interp = evaluateScript([0x9F, 0x11, 0xF5, 0x55], [0x0F], OpCodes.OP_RSHIFT);
      var result = interp.stack.pop();
      expect(HEX.encode(result), equals(toBitpattern('00000000000000010011111000100011')));
    });
  });

  var testFixture = (vector, bool expected, extraData) {
    var inputAmount = 0.0;
    if (extraData != null) {
      inputAmount = extraData[0] * 1e8;
    }

    // var hashbuf = List<int>.filled(32, 0);
    Transaction credtx = new Transaction();
    credtx.version = 1;
    var coinbaseUnlockBuilder = DefaultUnlockBuilder.fromScript(SVScript.fromString('OP_0 OP_0'));
    TransactionInput txCredInput =
    TransactionInput('0000000000000000000000000000000000000000000000000000000000000000', 0xffffffff, 0xffffffff, scriptBuilder: coinbaseUnlockBuilder);
    credtx.addInput(txCredInput);

    var flags = parseVerifyFlags(vector[2]);
    ScriptError expectedError = ScriptError.fromMnemonic(vector[3]);
    var thisTest = vector[1];

    try {
      var scriptSig = parseScriptString(vector[0]);
      var scriptPubkey = parseScriptString(vector[1]);

      //add output to spent Transaction
      var txOutLockBuilder = DefaultLockBuilder.fromScript(scriptPubkey);
      var txCredOut = TransactionOutput(BigInt.from(inputAmount), scriptPubkey);
      credtx.addOutput(txCredOut);
      credtx.serialize();

      //setup transaction ID of spent Transaction
      String prevTxId = credtx.id;

      var defaultUnlockBuilder = DefaultUnlockBuilder.fromScript(scriptSig);
      var spendtx = Transaction();
      spendtx.version = 1;
      var txSpendInput = TransactionInput(prevTxId, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: defaultUnlockBuilder);
      spendtx.addInput(txSpendInput);
      var txSpendOutput = TransactionOutput(BigInt.zero, SVScript());
      spendtx.addOutput(txSpendOutput);

      // var interp = new Interpreter();
      // var verified = interp.verifyScript(scriptSig, scriptPubkey, tx: spendtx, nin: 0, flags: flags, satoshis: BigInt.from(inputAmount));

      var interp = InterpreterV2();
      var verified = true;

      // interp.correctlySpends(scriptSig!, scriptPubkey, tx, index, flags, Coin.ZERO);
      interp.correctlySpends(scriptSig, scriptPubkey, spendtx, 0, flags, Coin.valueOf(BigInt.from(inputAmount)));


      if (!(expectedError == ScriptError.SCRIPT_ERR_OK)) {
        fail("${thisTest} is expected to fail");
      }
    } on ScriptException catch (e) {
      if (!(e.error == expectedError)) {
        print(thisTest);
        print(e);
        throw e;
      }
    }

    // expect(verified, equals(expected));
  };

  runScripTestFixtures(File fixtureFile) async {

    await fixtureFile
        .readAsString()
        .then((contents) => jsonDecode(contents))
        .then((jsonData) {
      List.from(jsonData).forEach((vect) {
        if (vect.length == 1) {
          return;
        }
        var extraData;
        if (vect[0] is List) {
          extraData = (vect as List<dynamic>).removeAt(0);
        }

        String fullScriptString = "${vect[0]} ${vect[1]}";
        bool expected = vect[3] == 'OK';
        String comment = "";
        if (vect.length > 4) {
          comment = vect[4];
        }

        var txt = "should ${vect[3]} script_tests vector : ${fullScriptString}${comment}";
        print(txt);

        testFixture(vect, expected, extraData);
      });
    });
  }

  test('bitcoin SV Node script evaluation fixtures', () async {
    await runScripTestFixtures(File("${Directory.current.path}/test/data/bitcoind/script_tests_svnode.json"));
  });

  test('bitcoind script evaluation fixtures', () async {
    await runScripTestFixtures(File("${Directory.current.path}/test/data/bitcoind/script_tests.json"));
  });

  dataDrivenValidTransactions(File testFixtures) async {
    var testName = "";
    await testFixtures
        .readAsString()
        .then((contents) => jsonDecode(contents))
        .then((jsonData) {
      List.from(jsonData).forEach((vect) {

        if (vect.length == 1) {
          testName = vect[0];
          print("Testing : ${testName}");
        }

        if (vect.length > 1) {
          Transaction spendingTx;

          try {
            var inputs = vect[0];
            var map = {};
            inputs.forEach((input) {
              var txid = input[0];
              var txoutnum = input[1];
              var scriptPubKeyStr = input[2];
              map[txid + ':' + txoutnum.toString()] = parseScriptString(scriptPubKeyStr);
            });

            spendingTx = Transaction.fromHex(vect[1]);
            spendingTx.verify();

            // System.out.println(test.get(1).asText());

            ///all this ceremony to extract Verify Flags
            var verifyFlags = parseVerifyFlags(vect[2]);

            for (int i = 0; i < spendingTx.inputs.length; i++) {
              TransactionInput input = spendingTx.inputs[i];
              if (input.prevTxnOutputIndex == 0xffffffff) {
                input.prevTxnOutputIndex = -1;
              }

              print("Spending INPUT : [${i}]");

              //reconstruct the key into our Map of Public Keys using the details from
              //the parsed transaction
              // String txId = HEX.encode(input.prevTxnId);
              String keyName = "${input.prevTxnId}:${input.prevTxnOutputIndex}";

              //assert that our parsed transaction has correctly extracted the provided
              //UTXO details
              expect(map.containsKey(keyName), true, reason: "Missing entry for scriptPubKey ${keyName}");
              var interp = InterpreterV2();
              interp.correctlySpends(input.script!, map[keyName], spendingTx, i, verifyFlags, Coin.ZERO);

              //TODO: Would be better to assert expectation that no exception is thrown ?
              //Ans: The whole of the Script Interpreter uses Exception-Handling for error-handling. So no,
              //     not without a deep refactor of the code.
            }
          } on ScriptException catch (e) {
            print(e.cause);
            // if (spendingTx != null)
            //   print(spendingTx);

            throw e;
          }
        }
      });
    });
  }

  dataDrivenInValidTransactions(File testFixtures) async {
    var testName = "";
    await testFixtures.readAsString().then((contents) => jsonDecode(contents)).then((jsonData) {
      List.from(jsonData).forEach((vect) {
        if (vect.length == 1) {
          testName = vect[0];
          print("Testing : ${testName}");
        }

        if (vect.length > 1) {
          Transaction spendingTx;
          bool valid = true;

          try {
            var inputs = vect[0];
            var map = {};
            inputs.forEach((input) {
              var txid = input[0];
              var txoutnum = input[1];
              var scriptPubKeyStr = input[2];
              map[txid + ':' + txoutnum.toString()] = parseScriptString(scriptPubKeyStr);
            });

            spendingTx = Transaction.fromHex(vect[1]);
            spendingTx.version = 1;
            try {
              spendingTx.verify();
            } on Exception catch (ex) {
              valid = false;
            }

            ///all this ceremony to extract Verify Flags
            var verifyFlags = parseVerifyFlags(vect[2]);

            for (int i = 0; i < spendingTx.inputs.length; i++) {
              TransactionInput input = spendingTx.inputs[i];
              if (input.prevTxnOutputIndex == 0xffffffff) {
                input.prevTxnOutputIndex = -1;
              }

              print("Spending INPUT : [${i}]");

              //reconstruct the key into our Map of Public Keys using the details from
              //the parsed transaction
              // String txId = HEX.encode(input.prevTxnId);
              String keyName = "${input.prevTxnId}:${input.prevTxnOutputIndex}";

              //assert that our parsed transaction has correctly extracted the provided
              //UTXO details
              // expect(scriptPubKeys.containsKey(keyName), true);
              var interp = InterpreterV2();
              interp.correctlySpends(input.script!, map[keyName], spendingTx, i, verifyFlags, Coin.ZERO);

              //TODO: Would be better to assert expectation that no exception is thrown ?
              //Ans: The whole of the Script Interpreter uses Exception-Handling for error-handling. So no,
              //     not without a deep refactor of the code.
            }
          } on Exception catch (e) {
            valid = false;
          }

          if (valid) fail(testName);
        }
      });
    });
  }


  test('bitcoin SV Node valid transaction evaluation fixtures', () async {
    await dataDrivenValidTransactions(File("${Directory.current.path}/test/data/bitcoind/tx_valid_svnode.json"));
  });


  test('bitcoin SV Node invalid transaction evaluation fixtures', () async {
    await dataDrivenInValidTransactions(File("${Directory.current.path}/test/data/bitcoind/tx_invalid_svnode.json"));
  });

  test('bitcoind valid transaction evaluation fixtures', () async {
    await dataDrivenValidTransactions(File("${Directory.current.path}/test/data/bitcoind/tx_valid.json"));
  });

  test('bitcoind invalid transaction evaluation fixtures', () async {
    await dataDrivenInValidTransactions(File("${Directory.current.path}/test/data/bitcoind/tx_invalid.json"));
  });

  CheckBinaryOpMagnetic(List<int> a, List<int> b, int op, List<int> expected) {
    var interp = evaluateScript(a, b, op);
    var result = interp.stack.pop();
    expect(result, equals(expected));
  }

  List<int> NegativeValtype(List<int> v) {
    var copy = v.sublist(0);
    if (copy.isNotEmpty) {
      copy[copy.length - 1] ^= 0x80;
    }

    // TODO: expose minimally encode as public method?
    return Interpreter().minimallyEncode(copy);
  }

  CheckMul(List<int> a, List<int> b, List<int> expected) {
    // Negative values for multiplication
    CheckBinaryOpMagnetic(a, b, OpCodes.OP_MUL, expected);
    CheckBinaryOpMagnetic(a, NegativeValtype(b), OpCodes.OP_MUL, NegativeValtype(expected));
    CheckBinaryOpMagnetic(NegativeValtype(a), b, OpCodes.OP_MUL, NegativeValtype(expected));
    CheckBinaryOpMagnetic(NegativeValtype(a), NegativeValtype(b), OpCodes.OP_MUL, expected);

    // Commutativity
    CheckBinaryOpMagnetic(b, a, OpCodes.OP_MUL, expected);
    CheckBinaryOpMagnetic(b, NegativeValtype(a), OpCodes.OP_MUL, NegativeValtype(expected));
    CheckBinaryOpMagnetic(NegativeValtype(b), a, OpCodes.OP_MUL, NegativeValtype(expected));
    CheckBinaryOpMagnetic(NegativeValtype(b), NegativeValtype(a), OpCodes.OP_MUL, expected);

    // Multiplication identities
    CheckBinaryOpMagnetic(a, [0x01], OpCodes.OP_MUL, a);
    CheckBinaryOpMagnetic(a, [0x81], OpCodes.OP_MUL, NegativeValtype(a));
    CheckBinaryOpMagnetic(a, [], OpCodes.OP_MUL, []);

    CheckBinaryOpMagnetic([0x01], b, OpCodes.OP_MUL, b);
    CheckBinaryOpMagnetic([0x81], b, OpCodes.OP_MUL, NegativeValtype(b));
    CheckBinaryOpMagnetic([], b, OpCodes.OP_MUL, []);
  }

  group('#OP_MUL tests from bitcoind', () {
    test('OP_MUL tests', () {
      CheckMul([0x05], [0x06], [0x1E]);
      CheckMul([0x05], [0x26], [0xBE, 0x00]);
      CheckMul([0x45], [0x26], [0x3E, 0x0A]);
      CheckMul([0x02], [0x56, 0x24], [0xAC, 0x48]);
      CheckMul([0x05], [0x26, 0x03, 0x32], [0xBE, 0x0F, 0xFA, 0x00]);
      CheckMul([0x06], [0x26, 0x03, 0x32, 0x04], [0xE4, 0x12, 0x2C, 0x19]);
      CheckMul([0xA0, 0xA0], [0xF5, 0xE4], [0x20, 0xB9, 0xDD, 0x0C]); // -20A0*-64F5=0CDDB920
      CheckMul([0x05, 0x26], [0x26, 0x03, 0x32], [0xBE, 0xB3, 0x71, 0x6D, 0x07]);
      CheckMul([0x06, 0x26], [0x26, 0x03, 0x32, 0x04], [0xE4, 0xB6, 0xA3, 0x85, 0x9F, 0x00]);
      CheckMul([0x05, 0x26, 0x09], [0x26, 0x03, 0x32], [0xBE, 0xB3, 0xC7, 0x89, 0xC9, 0x01]);
      CheckMul([0x06, 0x26, 0x09], [0x26, 0x03, 0x32, 0x04], [0xE4, 0xB6, 0xF9, 0xA1, 0x61, 0x26]);
      CheckMul([0x06, 0x26, 0x09, 0x34], [0x26, 0x03, 0x32, 0x04], [0xE4, 0xB6, 0xF9, 0x59, 0x05, 0x4F, 0xDA, 0x00]);
    });
  });

  group('#Empty and null script', () {
    test('Empty buffer should have value 0x00 in script', () {
      var s = SVScript().add(<int>[]);
      // script does not render anything so it appears invisible
      expect(s.toHex(), equals('00'));
      // yet there is a script chunk there
      expect(s.chunks.length, equals(1));
      expect(s.chunks[0].opcodenum, equals(0));
    });

    test('Zero value (0x00) buffer should have value 0x01 0x00 in script', () {
      var s = SVScript().add(<int>[0x00]);
      expect(s.toString(), equals('1 0x00'));
      expect(s.chunks.length, equals(1));
      expect(s.chunks[0].opcodenum, equals(1));
    });
  });

  group('#NegativeValType', () {
    test('should pass all tests', () {
      // Test zero values
      expect(SVScript().add(NegativeValtype([])).toHex(), equals(SVScript().add(<int>[]).toHex()));
      expect(SVScript().add(NegativeValtype([0x00])).toHex(), equals(SVScript().add(<int>[]).toHex()));
      expect(SVScript().add(NegativeValtype([0x80])).toHex(), equals(SVScript().add(<int>[]).toHex()));
      expect(SVScript().add(NegativeValtype([0x00, 0x00])).toHex(), equals(SVScript().add(<int>[]).toHex()));
      expect(SVScript().add(NegativeValtype([0x00, 0x80])).toHex(), equals(SVScript().add(<int>[]).toHex()));

      // Non-zero values
      expect(NegativeValtype([0x01]), equals([0x81]));
      expect(NegativeValtype([0x81]), equals([0x01]));
      expect(NegativeValtype([0x02, 0x01]), equals([0x02, 0x81]));
      expect(NegativeValtype([0x02, 0x81]), equals([0x02, 0x01]));
      expect(NegativeValtype([0xff, 0x02, 0x01]), equals([0xff, 0x02, 0x81]));
      expect(NegativeValtype([0xff, 0x02, 0x81]), equals([0xff, 0x02, 0x01]));
      expect(NegativeValtype([0xff, 0xff, 0x02, 0x01]), equals([0xff, 0xff, 0x02, 0x81]));
      expect(NegativeValtype([0xff, 0xff, 0x02, 0x81]), equals([0xff, 0xff, 0x02, 0x01]));

      // Should not be overly-minimized
      expect(NegativeValtype([0xff, 0x80]), equals([0xff, 0x00]));
      expect(NegativeValtype([0xff, 0x00]), equals([0xff, 0x80]));
    });
  });
}
