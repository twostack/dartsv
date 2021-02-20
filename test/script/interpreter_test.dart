import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/privatekey.dart';
import 'package:dartsv/src/script/interpreter.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/scriptflags.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
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

        if (flagstr.indexOf('MAGNETIC') != -1) {
            flags = flags | ScriptFlags.SCRIPT_ENABLE_MAGNETIC_OPCODES;
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


        test('should verify these simple transaction', () {
            // first we create a transaction
            var privateKey = new SVPrivateKey.fromWIF('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
            var publicKey = privateKey.publicKey;
            var fromAddress = publicKey.toAddress(NetworkType.TEST);
            var toAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
            var scriptPubkey = P2PKHLockBuilder(fromAddress).getScriptPubkey();
            var utxo = {
                "address": fromAddress,
                "txId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
                "outputIndex": 0,
                "scriptPubKey": scriptPubkey.toString(),
                "satoshis": BigInt.from(100000)
            };
            var tx = Transaction()
                .spendFromMap(utxo, scriptBuilder: P2PKHUnlockBuilder(publicKey))
                .spendTo(toAddress, BigInt.from(100000), scriptBuilder: P2PKHLockBuilder(toAddress));
            tx.signInput( 0, privateKey, sighashType: 1);
//                .signWith(privateKey, sighashType: 1);

            // we then extract the signature from the first input
            var inputIndex = 0;
            print(HEX.encode(hash160(HEX.decode(publicKey.toString()))));

            var signature = (tx.inputs[0].scriptBuilder as SignedUnlockBuilder).signatures[0];

            var scriptBuilder = P2PKHUnlockBuilder(publicKey);
            scriptBuilder.signatures.add(signature);
            var scriptSig = scriptBuilder.getScriptSig();

            var flags = ScriptFlags.SCRIPT_VERIFY_P2SH | ScriptFlags.SCRIPT_VERIFY_STRICTENC;
            var interpreter = Interpreter();

            var verified = interpreter.verifyScript(scriptSig, scriptPubkey, tx: tx, nin: inputIndex, flags: flags, satoshis: utxo["satoshis"]);
            expect(interpreter.errstr, equals(""));
            expect(verified, isTrue);
        });
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
        var flags = ScriptFlags.SCRIPT_VERIFY_P2SH | ScriptFlags.SCRIPT_ENABLE_MAGNETIC_OPCODES | ScriptFlags.SCRIPT_ENABLE_MONOLITH_OPCODES;
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
        var scriptSig = SVScript.fromBitcoindString(vector[0]);
        var scriptPubkey = SVScript.fromBitcoindString(vector[1]);
        var flags = getFlags(vector[2]);
        var inputAmount = 0.0;
        if (extraData != null) {
            inputAmount = extraData[0] * 1e8;
        }

        var hashbuf = List<int>(32);
        hashbuf.fillRange(0, hashbuf.length, 0);
        Transaction credtx = new Transaction();
        var coinbaseUnlockBuilder = DefaultUnlockBuilder();
        coinbaseUnlockBuilder.fromScript(SVScript.fromString('OP_0 OP_0'));
        TransactionInput txCredInput = TransactionInput(
            '0000000000000000000000000000000000000000000000000000000000000000',
            0xffffffff,
            SVScript(),
            BigInt.zero,
            0xffffffff,
            scriptBuilder: coinbaseUnlockBuilder
        );
        credtx.addInput(txCredInput);
        credtx.serialize(performChecks: false);

        //add output to spent Transaction
        var txOutLockBuilder = DefaultLockBuilder();
        txOutLockBuilder.fromScript(scriptPubkey);
        var txCredOut = TransactionOutput(scriptBuilder: txOutLockBuilder);
        txCredOut.satoshis = BigInt.from(inputAmount);
        txCredOut.script = scriptPubkey;
        credtx.addOutput(txCredOut);

        //setup transaction ID of spent Transaction
        String prevTxId = credtx.id;

        var defaultUnlockBuilder = DefaultUnlockBuilder();
        defaultUnlockBuilder.fromScript(scriptSig);
        var spendtx = Transaction();
        var txSpendInput = TransactionInput(
            prevTxId,
            0,
            scriptPubkey,
            BigInt.zero,
            TransactionInput.UINT_MAX,
            scriptBuilder: defaultUnlockBuilder
        );
        spendtx.addInput(txSpendInput);
        var txSpendOutput = TransactionOutput();
        txSpendOutput.script = SVScript();
        txSpendOutput.satoshis = BigInt.from(inputAmount);
        spendtx.addOutput(txSpendOutput);

        var interp = new Interpreter();
        var verified = interp.verifyScript(scriptSig, scriptPubkey, tx: spendtx, nin: 0, flags: flags, satoshis: BigInt.from(inputAmount));
        expect(verified, equals(expected), reason: interp.errstr);
    };


    test('bitcoind script evaluation fixtures', () async {
        await File("${Directory.current.path}/test/data/bitcoind/script_tests.json")
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
    });

    void testTransaction(List<dynamic> vector, bool expected){

        int c = 0;
        if (vector.length == 1) {
          return;
        };

        print(vector[0]);

        c++;
        var cc = c; // copy to local

//        it('should pass tx_' + (expected ? '' : 'in') + 'valid vector ' + cc, function () {
          var inputs = vector[0];
          var txhex = vector[1];

          var flags = getFlags(vector[2]);
          var map = {};
          inputs.forEach((input) {
            var txid = input[0];
            var txoutnum = input[1];
            var scriptPubKeyStr = input[2];
            if (txoutnum == -1) {
              txoutnum = 0xffffffff; // bitcoind casts -1 to an unsigned int
            }
            map[txid + ':' + txoutnum.toString()] = SVScript.fromBitcoindString(scriptPubKeyStr);
          });

          var tx = Transaction.fromHex(txhex);
          var allInputsVerified = true;
          int index = 0;
          tx.inputs.forEach((TransactionInput txin) {
//            if (txin.isNull()) {
//              return;
//            }
            var scriptSig = txin.script;
            var txidhex = txin.prevTxnId;
            var txoutnum = txin.prevTxnOutputIndex;
            var scriptPubkey = map[txidhex + ':' + txoutnum.toString()];
            expect(scriptPubkey, isNotNull);
            expect(scriptSig, isNotNull);
            var interp = Interpreter();
            var verified = interp.verifyScript(scriptSig, scriptPubkey, tx: tx, nin: index, flags: flags);
            if (!verified) {
              allInputsVerified = false;
            }
            index++;
          });

          var txVerified = tx.verify().isEmpty;
          allInputsVerified = allInputsVerified && txVerified;
          expect(allInputsVerified, equals(expected));
    }

    test('bitcoind valid transaction evaluation fixtures', () async {
        await File("${Directory.current.path}/test/data/bitcoind/tx_valid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((vect) {
                testTransaction(vect, true);
            });
        });
    });


    test('bitcoind invalid transaction evaluation fixtures', () async {
        await File("${Directory.current.path}/test/data/bitcoind/tx_invalid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((vect) {
                testTransaction(vect, false);
            });
        });
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
      expect(NegativeValtype([0xff, 0xff, 0x02, 0x01]),equals([0xff, 0xff, 0x02, 0x81]));
      expect(NegativeValtype([0xff, 0xff, 0x02, 0x81]),equals([0xff, 0xff, 0x02, 0x01]));

      // Should not be overly-minimized
      expect(NegativeValtype([0xff, 0x80]),equals([0xff, 0x00]));
      expect(NegativeValtype([0xff, 0x00]),equals([0xff, 0x80]));
    });
  });



    /*




  const debugScript = function (step, stack, altstack) {
    const script = (new Script()).add(step.opcode)
    // stack is array of buffers
    let stackTop = '>'
    for (let item in stack.reverse()) {
      console.log(`Step ${step.pc}: ${script}:${stackTop}${stack[item].toString('hex')}`)
      stackTop = ' '
    }
  }


   */

}

/*
'use strict'

var should = require('chai').should()
var bsv = require('../..')
var Interpreter = bsv.Script.Interpreter
var Transaction = bsv.Transaction
var PrivateKey = bsv.PrivateKey
var Script = bsv.Script
var BN = bsv.crypto.BN
var BufferWriter = bsv.encoding.BufferWriter
var Opcode = bsv.Opcode
var _ = require('lodash')


describe('Interpreter', function () {

  describe('#verify', function () {

  })

  describe('#script debugger', function () {
    it('debugger should fire while executing script', function () {
      var si = Interpreter()
      let debugCount = 0
      si.stepListener = function (step) {
        debugCount += 1
      }
      si.verify(Script('OP_1 OP_2 OP_ADD'), Script('OP_3 OP_EQUAL'))
      si.errstr.should.equal('')
      // two scripts. first one has 3 instructions. second one has 2 instructions
      debugCount.should.equal(3 + 2)
    })
    it('debugger error in callback should not kill executing script', function () {
      var si = Interpreter()
      si.stepListener = function (step) {
        throw new Error('This error is expected.')
      }
      si.verify(Script('OP_1 OP_2 OP_ADD'), Script(''))
      const result = [...si.stack.pop()]
      result.should.to.deep.equal([3])
      si.errstr.should.equal('')
      si.stack.length.should.equal(0)
    })
    it('script debugger should fire and not cause an error', function () {
      var si = Interpreter()
      si.stepListener = debugScript
      si.verify(Script('OP_1 OP_2 OP_ADD'), Script('OP_3 OP_EQUAL'))
      si.errstr.should.equal('')
    })
    it('script debugger should make copies of stack', function () {
      var si = Interpreter()
      let stk, stkval, altstk, altstkval
      si.stepListener = function (step, stack, altstack) {
        // stack is an array of buffers, interpreter must give us copies of stack so we can't mess it up
        console.log(step)
        console.log(stack)
        console.log(altstack)
        // these values will get overwritten each step but we only care about that final values
        stk = (stack === si.stack)
        stkval = (stack[0] === si.stack[0])
        altstk = (altstack === si.altstack)
        altstkval = (altstack[0] === si.altstack[0])
      }
      // alt stack is not copied to second script execution so just do everything in second script
      si.verify(Script(''), Script('OP_2 OP_TOALTSTACK OP_1'))
      console.log(si.stack)
      console.log(si.altstack)
      si.errstr.should.equal('')
      si.stack.length.should.equal(1)
      si.altstack.length.should.equal(1)
      stk.should.equal(false)
      stkval.should.equal(false)
      altstk.should.equal(false)
      altstkval.should.equal(false)
    })
  })







  describe('', function () {
    var testTxs = function (set, expected) {
      var c = 0
      set.forEach(function (vector) {
    }
    testTxs(txValid, true)
    testTxs(txInvalid, false)
  })
})


 */
