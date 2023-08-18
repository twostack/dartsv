import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/interpreter.dart';
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

  group('@castToBool', () {
    test('should cast these bufs to bool correctly', () {

      expect(Interpreter.castToBool(Uint8List.fromList(HEX.decode(BigInt.zero.toRadixString(16)))), equals(false));
      expect(Interpreter.castToBool(Uint8List.fromList(HEX.decode(BigInt.parse('0080', radix: 16).toRadixString(16)))), equals(false)); // negative 0
      expect(Interpreter.castToBool(Uint8List.fromList(HEX.decode(BigInt.one.toRadixString(16)))), equals(true));

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

      var interp = Interpreter();

      interp.correctlySpends(scriptSig, scriptPubkey, spendtx, 0, flags, Coin.valueOf(BigInt.from(inputAmount)));


      if (!(expectedError == ScriptError.SCRIPT_ERR_OK)) {
        fail("${thisTest} is expected to fail");
      }
    } on ScriptException catch (e) {
      if (!(e.error == expectedError)) {
        print("${e.error} - ${e.cause}");
        throw e;
      }
    }

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

  test('bitcoin SV Node Test vectors', () async {
    await runScripTestFixtures(File("${Directory.current.path}/test/data/bitcoind/script_tests_svnode.json"));
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
              var interp = Interpreter();
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
              var interp = Interpreter();
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

}
