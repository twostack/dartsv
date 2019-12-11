import 'dart:collection';
import 'dart:core';
import 'dart:core' as prefix0;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:hex/hex.dart';


class Stack {
    Queue<List<int>> _queue = new Queue<List<int>>();

    Stack();

    Stack.fromQueue(Queue<List<int>> queue){
        this._queue = Queue.from(queue);
    }


    void push(List<int> item) {
        _queue.addLast(List.from(item));
    }

    int get length => _queue.length;

    void removeAll() {
        this._queue.clear();
    }

    Stack slice() {
        return Stack.fromQueue(_queue);
    }

    //peek up to "index"
    List<int> peek({int index = -1}) {
        if (index > 0) {
            throw new StackOverflowError();
        }

        if (index > _queue.length - 1) {
            throw new Exception("Can't peek past the first element");
        }
        var retval = _queue.elementAt(_queue.length + index); //FIXME: Validate this !
        retval.runtimeType;
        return retval;

    }

    List<int> pop() {
        return _queue.removeLast();
    }

    List<List<int>> splice(int index, int howMany, {List<int> values}) {
        List<List<int>> buffer = _queue.toList();

        List<List<int>> removedItems = buffer.getRange(index, index+howMany).toList();
        buffer.removeRange(index, index+howMany);

        if (values != null) {
            buffer.insert(index, values);
        }
        this._queue = Queue.from(buffer);

        return removedItems;

    }

    /// Replace item at 'index' with 'value'
    /// FIXME: Validate this works as expected
    void replaceAt(int index, List<int> value) {
        List<List<int>> buffer = _queue.toList();
        buffer.removeAt(index);
        buffer.insert(index, value);
        _queue = Queue.from(buffer);
    }
}

class Interpreter {

    static final MAX_SCRIPT_ELEMENT_SIZE = 520;
    static const MAXIMUM_ELEMENT_SIZE = 4;

    static final LOCKTIME_THRESHOLD = 500000000;
    static final LOCKTIME_THRESHOLD_BN = BigInt.from(LOCKTIME_THRESHOLD);

// flags taken from bitcoind
// bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    static final SCRIPT_VERIFY_NONE = 0;

// Evaluate P2SH subscripts (softfork safe, BIP16).
    static final SCRIPT_VERIFY_P2SH = (1 << 0);


    static List<int> TRUE = <int>[1];
    static List<int> FALSE = <int>[];

// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
// Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
// skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
    static final SCRIPT_VERIFY_STRICTENC = (1 << 1);

// Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    static final SCRIPT_VERIFY_DERSIG = (1 << 2);

// Pa non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
// (softfork safe, BIP62 rule 5).
    static final SCRIPT_VERIFY_LOW_S = (1 << 3);

// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    static final SCRIPT_VERIFY_NULLDUMMY = (1 << 4);

// Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    static final SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5);

// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
// any other push causes the script to fail (BIP62 rule 3).
// In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
// (softfork safe)
    static final SCRIPT_VERIFY_MINIMALDATA = (1 << 6);

// Discourage use of NOPs reserved for upgrades (NOP1-10)
//
// Provided so that nodes can avoid accepting or mining transactions
// containing executed NOP's whose meaning may change after a soft-fork,
// thus rendering the script invalid; with this flag set executing
// discouraged NOPs fails the script. This verification flag will never be
// a mandatory flag applied to scripts in a block. NOPs that are not
// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    static final SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7);

// Require that only a single stack element remains after evaluation. This
// changes the success criterion from "At least one stack element must
// remain, and when interpreted as a boolean, it must be true" to "Exactly
// one stack element must remain, and when interpreted as a boolean, it must
// be true".
// (softfork safe, BIP62 rule 6)
// Note: CLEANSTACK should never be used without P2SH or WITNESS.
    static final SCRIPT_VERIFY_CLEANSTACK = (1 << 8);

// Cstatic final LTV See BIP65 for details.
    static final SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9);

// support CHECKSEQUENCEVERIFY opcode
//
// See BIP112 for details
    static final SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10);

// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
// 0x01 or empty vector
//
    static final SCRIPT_VERIFY_MINIMALIF = (1 << 13);

// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
//
    static final SCRIPT_VERIFY_NULLFAIL = (1 << 14);

// Public keys in scripts must be compressed
    static final SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = (1 << 15);

// Do we accept signature using SIGHASH_FORKID
//
    static final SCRIPT_ENABLE_SIGHASH_FORKID = (1 << 16);

// Do we accept activate replay protection using a different fork id.
//
    static final SCRIPT_ENABLE_REPLAY_PROTECTION = (1 << 17);

// Enable new opcodes.
//
    static final SCRIPT_ENABLE_MONOLITH_OPCODES = (1 << 18);

// Are the Magnetic upgrade opcodes enabled?
//
    static final SCRIPT_ENABLE_MAGNETIC_OPCODES = (1 << 19);

/* Below flags apply in the context of BIP 68 */
    /**
     * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
     * lock-time.
     */
    static final SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
     * the relative lock-time has units of 512 seconds, otherwise it specifies
     * blocks with a granularity of 1.
     */
    static final SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
     * extract that lock-time from the sequence field.
     */
    static final SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    Stack _stack = new Stack();
    Stack _altStack = new Stack();
    int _pc = 0;
    int _pbegincodehash = 0;
    int _nOpCount = 0;
    List _vfExec = List();
    String _errStr = "";
    int _flags = 0;

    /**/
    SVScript _script;
    Transaction _tx;
    int _nin;
    BigInt _satoshis;

    /**/


    Stack get stack => _stack;

    Stack get altStack => _altStack;

    int get pc => _pc;

    int get pbegincodehash => _pbegincodehash;

    int get nOpCount => this._nOpCount;

    List get vfExec => _vfExec; //???
    String get errstr => _errStr;

    int get flags => _flags;

    SVScript get script => _script;

    Interpreter();

    Interpreter.fromScript(SVScript script, int flags){
       this._script = script;
       this._flags = flags;
    }

    bool _isMinimallyEncoded(buf, {nMaxNumSize = MAXIMUM_ELEMENT_SIZE}) {
        if (buf.length > nMaxNumSize) {
            return false;
        }

        if (buf.length > 0) {
            // Check that the number is encoded with the minimum possible number
            // of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if ((buf[buf.length - 1] & 0x7f) == 0) {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set it
                // would conflict with the sign bit. An example of this case is
                // +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) == 0) {
                    return false;
                }
            }
        }
        return true;
    }

    List<int> minimallyEncode (List<int> buf) {
        if (buf.length == 0) {
            return buf;
        }

        // If the last byte is not 0x00 or 0x80, we are minimally encoded.
        var last = buf[buf.length - 1];
        if (last & 0x7f != 0) {
            return buf;
        }

        // If the script is one byte long, then we have a zero, which encodes as an
        // empty array.
        if (buf.length == 1) {
            return List<int>();
        }

        // If the next byte has it sign bit set, then we are minimaly encoded.
        if (buf[buf.length - 2] & 0x80 != 0) {
            return buf;
        }

        // We are not minimally encoded, we need to figure out how much to trim.
        for (var i = buf.length - 1; i > 0; i--) {
            // We found a non zero byte, time to encode.
            if (buf[i - 1] != 0) {
                if (buf[i - 1] & 0x80 != 0) {
                    // We found a byte with it sign bit set so we need one more
                    // byte.
                    buf[i++] = last;
                } else {
                    // the sign bit is clear, we can use it.
                    buf[i - 1] |= last;
                }

                return buf.sublist(0, i);
            }
        }

        // If we found the whole thing is zeros, then we have a zero.
        return List<int>();
    }

    bool verifyScript(SVScript scriptSig, SVScript scriptPubkey, {Transaction tx , int nin = 0, int flags = 0, BigInt satoshis}) {
        if (tx == null) {
            tx = new Transaction();
        }


        // If FORKID is enabled, we also ensure strict encoding.
        if (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID != 0) {
            flags |= Interpreter.SCRIPT_VERIFY_STRICTENC;

            // If FORKID is enabled, we need the input amount.
            if (satoshis == null) {
                throw ScriptException('internal error - need satoshis to verify FORKID transactions');
            }
        }


        this._script = scriptSig;
        this._tx = tx;
        this._nin = nin;
        this._flags = flags;
        this._satoshis = satoshis;

        Stack stackCopy;

        if ((flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.isPushOnly()) {
            this._errStr = 'SCRIPT_ERR_SIG_PUSHONLY';
            return false;
        };

        // evaluate scriptSig
        if (!this.evaluate()) {
            return false;
        }

        if (flags & Interpreter.SCRIPT_VERIFY_P2SH != 0) {
            stackCopy = this._stack.slice();
        }

        var stack = this._stack;
        this.initialize();
        this.set({
            "script": scriptPubkey,
            "stack": stack,
            "tx": tx,
            "nin": nin,
            "flags": flags,
            "satoshis": satoshis
        });

        // evaluate scriptPubkey
        if (!this.evaluate()) {
            return false;
        }

        if (this._stack.length == 0) {
            this._errStr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT';
            return false;
        }

        List<int> buf = this._stack.peek(); //[this._stack.length - 1];
        if (!castToBool(buf)) {
            this._errStr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK';
            return false;
        }

        // Additional validation for spend-to-script-hash transactions:
        if ((flags & Interpreter.SCRIPT_VERIFY_P2SH != 0) && scriptPubkey.isScriptHashOut()) {
            // scriptSig must be literals-only or validation fails
            if (!scriptSig.isPushOnly()) {
                this._errStr = 'SCRIPT_ERR_SIG_PUSHONLY';
                return false;
            }

            // stackCopy cannot be empty here, because if it was the
            // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
            // an empty stack and the EvalScript above would return false.
            if (stackCopy.length == 0) {
                throw new InterpreterException('internal error - stack copy empty');
            }

            var redeemScriptSerialized = stackCopy.peek(); // [stackCopy.length - 1];
            var redeemScript = SVScript.fromByteArray(Uint8List.fromList(redeemScriptSerialized));
            stackCopy.pop();

            this.initialize();
            this.set({
                "script": redeemScript,
                "stack": stackCopy,
                "tx": tx,
                "nin": nin,
                "flags": flags,
                "satoshisBN": satoshis
            });

            // evaluate redeemScript
            if (!this.evaluate()) {
                return false;
            }

            if (stackCopy.length == 0) {
                this._errStr = 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK';
                return false;
            }

            if (!castToBool(stackCopy.peek())) {
                this._errStr = 'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK';
                return false;
            }
        }

        // The CLEANSTACK check is only performed after potential P2SH evaluation,
        // as the non-P2SH evaluation of a P2SH script will obviously not result in
        // a clean stack (the P2SH inputs remain). The same holds for witness
        // evaluation.
        if ((flags & Interpreter.SCRIPT_VERIFY_CLEANSTACK) != 0) {
            // Disallow CLEANSTACK without P2SH, as otherwise a switch
            // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
            // softfork (and P2SH should be one).
            if ((flags & Interpreter.SCRIPT_VERIFY_P2SH) == 0) {
                throw new InterpreterException('internal error - CLEANSTACK without P2SH');
            }

            if (stackCopy.length != 1) {
                this._errStr = 'SCRIPT_ERR_CLEANSTACK';
                return false;
            }
        }

        return true;
    }

// Ported from moneyButton-bsv, which in turn...
// Translated from bitcoind's CheckSignatureEncoding
//
    checkSignatureEncoding(List<int> buf, int flags) {
        var sig;
        var errStr;

        // Empty signature. Not strictly DER encoded, but allowed to provide a
        // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
        if (buf.isEmpty) {
            return true;
        }

        if ((flags & (Interpreter.SCRIPT_VERIFY_DERSIG | Interpreter.SCRIPT_VERIFY_LOW_S | Interpreter.SCRIPT_VERIFY_STRICTENC)) != 0 && !SVSignature.isTxDER(HEX.encode(buf))) {
            errStr = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT';
            return false;
        } else if ((flags & Interpreter.SCRIPT_VERIFY_LOW_S) != 0) {
            sig = SVSignature.fromTxFormat(HEX.encode(buf));
            if (!sig.hasLowS()) {
                errStr = 'SCRIPT_ERR_SIG_DER_HIGH_S';
                return false;
            }
        } else if ((flags & Interpreter.SCRIPT_VERIFY_STRICTENC) != 0) {
            sig = SVSignature.fromTxFormat(HEX.encode(buf));
            if (!sig.hasDefinedHashtype()) {
                errStr = 'SCRIPT_ERR_SIG_HASHTYPE';
                return false;
            }

            if (!(flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID != 0) &&
                (sig.nhashtype & SighashType.SIGHASH_FORKID != 0)) {
                errStr = 'SCRIPT_ERR_ILLEGAL_FORKID';
                return false;
            }

            if ((flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID != 0) &&
                !(sig.nhashtype & SighashType.SIGHASH_FORKID != 0)) {
                errStr = 'SCRIPT_ERR_MUST_USE_FORKID';
                return false;
            }
        }

        return true;
    }


    bool evaluate() {
        // TODO: script size should be configurable. no magic numbers
        if (this._script
            .buffer.length > 10000) { //FIXME: Does BSV still limit script size to 10k ???
            this._errStr = 'SCRIPT_ERR_SCRIPT_SIZE';
            return false;
        }

        try {
            while (this._pc < this._script.chunks.length) {
                var thisStep = {
                    "pc": this._pc,
                    "opcode": this._script.chunks[this.pc].opcodenum
                };

                bool fSuccess = this._step();
                if (!fSuccess) {
                    return false;
                }
                this._callbackStep(thisStep);
            }

            // Size limits
            if (this._stack.length + this._altStack.length > 1000) {
                this._errStr = 'SCRIPT_ERR_STACK_SIZE';
                return false;
            }
        } catch (e) {
            this._errStr = 'SCRIPT_ERR_UNKNOWN_ERROR: ' + e.toString();
            return false;
        }

        if (this.vfExec.isNotEmpty) {
            this._errStr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL';
            return false;
        }

        return true;
    }

    void clearStacks() {
        this._stack.removeAll();
        this._altStack.removeAll();
    }

    void initialize() {
        this._stack = new Stack.fromQueue(Queue<List<int>>());
        this._altStack = new Stack.fromQueue(Queue<List<int>>());
        this._pc = 0;
        this._pbegincodehash = 0;
        this._nOpCount = 0;
        this._vfExec = [];
        this._errStr = '';
        this._flags = 0;
    }

    void set(Map map) {
        this._stack = map["stack"];
        this._script = map["script"];
        this._tx = map["tx"];
        this._nin = map["nin"];
        this._flags = map["flags"];
        this._satoshis = map["satoshis"];
    }


    castBigIntToBool(BigInt value) {
        if (value == BigInt.zero){
            return false;
        }

        return true;
    }

    bool castToBool(List<int> buf) {
        for (var i = 0; i < buf.length; i++) {
            if (buf[i] != 0) {
                // can be negative zero
                if (i == buf.length - 1 && buf[i] == 0x80) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    ///
    /// * Based on the inner loop of bitcoind's EvalScript function
    /// * bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    ///
    bool _step() {
//  var self = this;

//        stacktop(int i) {
//            return this._stack.peek(); //FIXME: stacktop() is reduntant. Refactor !
//        }

        bool isOpCodesDisabled(int opcode) {
            switch (opcode) {
                case OpCodes.OP_2MUL:
                case OpCodes.OP_2DIV:
                // Disabled opcodes.
                    return true;

                case OpCodes.OP_INVERT:
                case OpCodes.OP_MUL:
                case OpCodes.OP_LSHIFT:
                case OpCodes.OP_RSHIFT:
                // OpCodess that have been reenabled.
                    if ((this._flags & Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES) == 0) {
                        return true;
                    }
                    break;
                case OpCodes.OP_DIV:
                case OpCodes.OP_MOD:
                case OpCodes.OP_SPLIT:
                case OpCodes.OP_CAT:
                case OpCodes.OP_AND:
                case OpCodes.OP_OR:
                case OpCodes.OP_XOR:
                case OpCodes.OP_BIN2NUM:
                case OpCodes.OP_NUM2BIN:
                // OpCodes that have been reenabled.
                    if ((this._flags & Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES) == 0) {
                        return true;
                    }
                    break;
                default:
                    break;
            }

            return false;
        }

        bool fRequireMinimal = (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) != 0; //FIXME: This is somehow used in JS BigNumber class

        // bool fExec = !count(vfExec.begin(), vfExec.end(), false);
        bool fExec = !this.vfExec.contains(false);
        var spliced, n, x1, x2, subscript;
        BigInt bn, bn1, bn2;
        List<int> buf1, buf2, bufPubkey, bufSig, buf;
        SVSignature sig;
        SVPublicKey pubkey;
        var fValue, fSuccess;

        // Read instruction
        var chunk = this._script.chunks[this.pc];
        this._pc++; //FIXME: global var f*ckery. Looks like index pointer into script chunks
        var opcodenum = chunk.opcodenum;
        if (opcodenum == null) {
            this._errStr = 'SCRIPT_ERR_UNDEFINED_OPCODE';
            return false;
        }
        if (chunk.buf.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
            this._errStr = 'SCRIPT_ERR_PUSH_SIZE';
            return false;
        }

        // Note how OpCodes.OP_RESERVED does not count towards the opcode limit.
        if (opcodenum > OpCodes.OP_16 && ++_nOpCount > 201) {
            this._errStr = 'SCRIPT_ERR_OP_COUNT';
            return false;
        }

        if (isOpCodesDisabled(opcodenum)) {
            this._errStr = 'SCRIPT_ERR_DISABLED_OPCODE';
            return false;
        }

        if (fExec && opcodenum >= 0 && opcodenum <= OpCodes.OP_PUSHDATA4) {
            if (fRequireMinimal && !this._script.checkMinimalPush(this._pc - 1)) {
                this._errStr = 'SCRIPT_ERR_MINIMALDATA';
                return false;
            }
            if (chunk.len != chunk.buf.length) {
                throw new InterpreterException("Length of push value not equal to length of data (${chunk.len},${chunk.buf.length})");
            }else if (chunk.buf.isEmpty) {
                this._stack.push(<int>[]);
            } else {
                this._stack.push(chunk.buf);
            }
        } else if (fExec || (OpCodes.OP_IF <= opcodenum && opcodenum <= OpCodes.OP_ENDIF)) {
            switch (opcodenum) {
            // Push value
                case OpCodes.OP_1NEGATE:
                case OpCodes.OP_1:
                case OpCodes.OP_2:
                case OpCodes.OP_3:
                case OpCodes.OP_4:
                case OpCodes.OP_5:
                case OpCodes.OP_6:
                case OpCodes.OP_7:
                case OpCodes.OP_8:
                case OpCodes.OP_9:
                case OpCodes.OP_10:
                case OpCodes.OP_11:
                case OpCodes.OP_12:
                case OpCodes.OP_13:
                case OpCodes.OP_14:
                case OpCodes.OP_15:
                case OpCodes.OP_16:
                // ( -- value)
                // ScriptNum bn((int)opcode - (int)(OpCodes.OP_1 - 1));
                    n = opcodenum - (OpCodes.OP_1 - 1);
                    buf = toScriptNumBuffer(BigInt.from(n));
                    this._stack.push(buf);
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                    break;

            //
            // Control
            //
                case OpCodes.OP_NOP:
                    break;

//                case OpCodes.OP_NOP2: //same numeric as CHECKLOCKTIMEVERIFY. Core buggery.
                case OpCodes.OP_CHECKLOCKTIMEVERIFY:
                    if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY != 0)) {
                        // not enabled; treat as a NOP2
                        if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0) {
                            this._errStr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS';
                            return false;
                        }
                        break;
                    }

                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    var nLockTime = fromScriptNumBuffer(Uint8List.fromList(this._stack.peek()), fRequireMinimal, nMaxNumSize: 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < BigInt.zero) {
                        this._errStr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME';
                        return false;
                    }

                    // Actually compare the specified lock time with the transaction.
                    if (!this.checkLockTime(nLockTime)) {
                        this._errStr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME';
                        return false;
                    }
                    break;

//      case OpCodes.OP_NOP3:
                case OpCodes.OP_CHECKSEQUENCEVERIFY:
                    if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY != 0)) {
                        // not enabled; treat as a NOP3
                        if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0) {
                            this._errStr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS';
                            return false;
                        }
                        break;
                    }

                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    // nSequence, like nLockTime, is a 32-bit unsigned
                    // integer field. See the comment in CHECKLOCKTIMEVERIFY
                    // regarding 5-byte numeric operands.

                    var nSequence = fromScriptNumBuffer(Uint8List.fromList(this._stack.peek()), fRequireMinimal, nMaxNumSize: 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < BigInt.zero) {
                        this._errStr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME';
                        return false;
                    }

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & BigInt.from(SEQUENCE_LOCKTIME_DISABLE_FLAG)) != BigInt.zero) {
                        break;
                    }

                    // Actually compare the specified lock time with the transaction.
                    if (!this.checkSequence(nSequence)) {
                        this._errStr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME';
                        return false;
                    }
                    break;

                case OpCodes.OP_NOP1:
                case OpCodes.OP_NOP4:
                case OpCodes.OP_NOP5:
                case OpCodes.OP_NOP6:
                case OpCodes.OP_NOP7:
                case OpCodes.OP_NOP8:
                case OpCodes.OP_NOP9:
                case OpCodes.OP_NOP10:
                    if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0) {
                        this._errStr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS';
                        return false;
                    }
                    break;

                case OpCodes.OP_IF:
                case OpCodes.OP_NOTIF:
                // <expression> if [statements] [else [statements]] endif
                // bool fValue = false;
                    fValue = false;
                    if (fExec) {
                        if (this._stack.length < 1) {
                            this._errStr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL';
                            return false;
                        }
                        buf = this._stack.peek();

                        if (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALIF != 0) {
                            if (buf.length > 1) {
                                this._errStr = 'SCRIPT_ERR_MINIMALIF';
                                return false;
                            }
                            if (buf.length == 1 && buf[0] != 1) {
                                this._errStr = 'SCRIPT_ERR_MINIMALIF';
                                return false;
                            }
                        }
                        fValue = castToBool(buf);
                        if (opcodenum == OpCodes.OP_NOTIF) {
                            fValue = !fValue;
                        }
                        this._stack.pop();
                    }
                    this.vfExec.add(fValue);
                    break;

                case OpCodes.OP_ELSE:
                    if (this.vfExec.isEmpty) {
                        this._errStr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL';
                        return false;
                    }
                    this.vfExec[this.vfExec.length - 1] = !this.vfExec[this.vfExec.length - 1];
                    break;

                case OpCodes.OP_ENDIF:
                    if (this.vfExec.isEmpty) {
                        this._errStr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL';
                        return false;
                    }
                    this.vfExec.removeLast();
                    break;

                case OpCodes.OP_VERIFY:
                // (true -- ) or
                // (false -- false) and return
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = this._stack.peek();
                    fValue = castToBool(buf);
                    if (fValue) {
                        this._stack.pop();
                    } else {
                        this._errStr = 'SCRIPT_ERR_VERIFY';
                        return false;
                    }
                    break;

                case OpCodes.OP_RETURN:
                    this._errStr = 'SCRIPT_ERR_OP_RETURN';
                    return false;
            // break // unreachable

            //
            // Stack ops
            //
                case OpCodes.OP_TOALTSTACK:
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._altStack.push(this._stack.pop());
                    break;

                case OpCodes.OP_FROMALTSTACK:
                    if (this._altStack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION';
                        return false;
                    }
                    this._stack.push(this._altStack.pop());
                    break;

                case OpCodes.OP_2DROP:
                // (x1 x2 -- )
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.pop();
                    this._stack.pop();
                    break;

                case OpCodes.OP_2DUP:
                // (x1 x2 -- x1 x2 x1 x2)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = this._stack.peek(index: -2);
                    buf2 = this._stack.peek();
                    this._stack.push(buf1);
                    this._stack.push(buf2);
                    break;

                case OpCodes.OP_3DUP:
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (this._stack.length < 3) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = this._stack.peek(index: -3);
                    buf2 = this._stack.peek(index: -2);
                    var buf3 = this._stack.peek();
                    this._stack.push(buf1);
                    this._stack.push(buf2);
                    this._stack.push(buf3);
                    break;

                case OpCodes.OP_2OVER:
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (this._stack.length < 4) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = this._stack.peek(index: -4);
                    buf2 = this._stack.peek(index: -3);
                    this._stack.push(buf1);
                    this._stack.push(buf2);
                    break;

                case OpCodes.OP_2ROT:
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (this._stack.length < 6) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    spliced = this._stack.splice(this._stack.length - 6, 2); //FIXME: Splice needs IMPLEMENTATION
                    this._stack.push(spliced[0]);
                    this._stack.push(spliced[1]);
                    break;

                case OpCodes.OP_2SWAP:
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (this._stack.length < 4) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    spliced = this._stack.splice(this._stack.length - 4, 2);
                    this._stack.push(spliced[0]);
                    this._stack.push(spliced[1]);
                    break;

                case OpCodes.OP_IFDUP:
                // (x - 0 | x x)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = this._stack.peek();
                    fValue = castToBool(buf);
                    if (fValue) {
                        this._stack.push(buf);
                    }
                    break;

                case OpCodes.OP_DEPTH:
                // -- stacksize
                    buf = toScriptNumBuffer(BigInt.from(this._stack.length));
//                    buf = HEX.decode(BigInt.from(this._stack.length).toRadixString(16));
                    if (this._stack.length == 0){
                        buf = []; //don't push array with zero value, push empty string instead
                    }

                    this._stack.push(buf);
                    break;

                case OpCodes.OP_DROP:
                // (x -- )
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.pop();
                    break;

                case OpCodes.OP_DUP:
                // (x -- x x)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.push(this._stack.peek());
                    break;

                case OpCodes.OP_NIP:
                // (x1 x2 -- x2)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.splice(this._stack.length - 2, 1);
                    break;

                case OpCodes.OP_OVER:
                // (x1 x2 -- x1 x2 x1)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.push(this._stack.peek(index: -2));
                    break;

                case OpCodes.OP_PICK:
                case OpCodes.OP_ROLL:
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = this._stack.peek();
                    bn = fromScriptNumBuffer(Uint8List.fromList(buf), fRequireMinimal);
                    n = bn.toInt();
                    this._stack.pop();
                    if (n < 0 || n >= this._stack.length) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = this._stack.peek(index: -n - 1);
                    if (opcodenum == OpCodes.OP_ROLL) {
                        this._stack.splice(this._stack.length - n - 1, 1);
                    }
                    this._stack.push(buf);
                    break;

                case OpCodes.OP_ROT:
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                    if (this._stack.length < 3) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    x1 = this._stack.peek(index: -3);
                    x2 = this._stack.peek(index: -2);
                    var x3 = this._stack.peek(index: -1);
                    this._stack.replaceAt(this._stack.length - 3, x2);
                    this._stack.replaceAt(this._stack.length - 2, x3);
                    this._stack.replaceAt(this._stack.length - 1, x1);
                    break;

                case OpCodes.OP_SWAP:
                // (x1 x2 -- x2 x1)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    x1 = this._stack.peek(index: -2);
                    x2 = this._stack.peek(index: -1);
                    this._stack.replaceAt(this._stack.length - 2, x2);
                    this._stack.replaceAt(this._stack.length - 1, x1);
                    break;

                case OpCodes.OP_TUCK:
                // (x1 x2 -- x2 x1 x2)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    this._stack.splice(this._stack.length - 2, 0, values: stack.peek());
                    break;

                case OpCodes.OP_SIZE:
                // (in -- in size)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    bn = BigInt.from(stack
                        .peek()
                        .length);
                    this.stack.push(toScriptNumBuffer(bn));
//                    this._stack.push(HEX.decode(bn.toRadixString(16)));
                    break;

            //
            // Bitwise logic
            //
                case OpCodes.OP_AND:
                case OpCodes.OP_OR:
                case OpCodes.OP_XOR:
                // (x1 x2 - out)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = stack.peek(index: -2);
                    buf2 = stack.peek(index: -1);

                    // Inputs must be the same size
                    if (buf1.length != buf2.length) {
                        this._errStr = 'SCRIPT_ERR_INVALID_OPERAND_SIZE';
                        return false;
                    }

                    // To avoid allocating, we modify vch1 in place.
                    switch (opcodenum) {
                        case OpCodes.OP_AND:
                            for (var i = 0; i < buf1.length; i++) {
                                buf1[i] &= buf2[i];
                            }
                            break;
                        case OpCodes.OP_OR:
                            for (var i = 0; i < buf1.length; i++) {
                                buf1[i] |= buf2[i];
                            }
                            break;
                        case OpCodes.OP_XOR:
                            for (var i = 0; i < buf1.length; i++) {
                                buf1[i] ^= buf2[i];
                            }
                            break;
                        default:
                            break;
                    }

                    // And pop vch2.
                    this._stack.pop();
                    break;

                    //FIXME: Using a List<int> for the stack seems to be problematic under certain circumstances
                    //       Consider refactoring to Uint8List()
                case OpCodes.OP_INVERT:
                // (x -- out)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                    }
                    buf = Uint8List.fromList(stack.peek());
                    for (var i = 0; i < buf.length; i++) {
                        buf[i] = ~buf[i];
                    }
                    stack.replaceAt(stack.length - 1, buf); //replace item at top with modified value
                    break;

                case OpCodes.OP_LSHIFT:
                case OpCodes.OP_RSHIFT:
                // (x n -- out)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = stack.peek(index: -2);
                    if (buf1.isEmpty) {
                        this._stack.pop();
                    } else {
//                        bn1 = BigInt.tryParse(HEX.encode(buf1), radix: 16) ?? BigInt.zero;
//                        bn2 = BigInt.tryParse(HEX.encode(stack.peek()), radix: 16) ?? BigInt.zero;

                        bn1 = decodeBigInt(buf1);
                        bn2 = fromScriptNumBuffer(Uint8List.fromList(stack.peek()), fRequireMinimal);

                        n = bn2.toInt();
                        if (n < 0) {
                            this._errStr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE';
                            return false;
                        }
                        this._stack.pop();
                        this._stack.pop();
                        BigInt shifted;


                        // bitcoin client implementation of l/rshift is unconventional, therefore this implementation is a bit unconventional
                        // bn library has shift functions however it expands the carried bits into a new byte
                        // in contrast to the bitcoin client implementation which drops off the carried bits
                        // in other words, if operand was 1 byte then we put 1 byte back on the stack instead of expanding to more shifted bytes
                        if (opcodenum == OpCodes.OP_LSHIFT) {
                            //Dart BigInt automagically right-pads the shifted bits
                            shifted = bn1 << n; // bn1.ushln(n);
                        }
                        if (opcodenum == OpCodes.OP_RSHIFT) {
                            shifted = bn1 >> n;
                        }


                        var padding = shifted.toRadixString(16).padLeft(buf1.length*2, '0');

                        if (n > 0) {
                            var shiftedList = HEX.decode(padding);
                            this._stack.push( shiftedList.sublist(shiftedList.length - buf1.length));
                        }else{
                            this._stack.push( HEX.decode(shifted.toRadixString(16)));  //if no shift occured then don't drop bits
                        }

                    }
                    break;

                case OpCodes.OP_EQUAL:
                case OpCodes.OP_EQUALVERIFY:
                // case OpCodes.OP_NOTEQUAL: // use Opcode.OP_NUMNOTEQUAL
                // (x1 x2 - bool)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = stack.peek(index: -2);
                    buf2 = stack.peek(index: -1);
                    bool fEqual = ListEquality().equals(buf1, buf2);
                    this._stack.pop();
                    this._stack.pop();
                    this._stack.push(fEqual ? TRUE : FALSE); //FIXME: pushing true and false to stack. Is works ?
                    if (opcodenum == OpCodes.OP_EQUALVERIFY) {
                        if (fEqual) {
                            this._stack.pop();
                        } else {
                            this._errStr = 'SCRIPT_ERR_EQUALVERIFY';
                            return false;
                        }
                    }
                    break;

            //
            // Numeric
            //
                case OpCodes.OP_1ADD:
                case OpCodes.OP_1SUB:
                case OpCodes.OP_NEGATE:
                case OpCodes.OP_ABS:
                case OpCodes.OP_NOT:
                case OpCodes.OP_0NOTEQUAL:
                // (in -- out)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = stack.peek();
                    bn = fromScriptNumBuffer(Uint8List.fromList(buf), fRequireMinimal);
//                    bn = BigInt.parse(HEX.encode(buf), radix: 16);
                    switch (opcodenum) {
                        case OpCodes.OP_1ADD:
                            bn = bn + BigInt.one;
                            break;
                        case OpCodes.OP_1SUB:
                            bn = bn - BigInt.one;
                            break;
                        case OpCodes.OP_NEGATE:
                            bn = -bn;
                            break;
                        case OpCodes.OP_ABS:
                            if (bn < BigInt.zero) {
                                bn = -bn;
                            }
                            break;
                        case OpCodes.OP_NOT:
                            if (bn == BigInt.zero) {
                                bn = BigInt.one;
                            }else if (bn == BigInt.one) {
                                bn = BigInt.zero;
                            }else {
                                bn = BigInt.zero;
                            }

                            break;
                        case OpCodes.OP_0NOTEQUAL:
                            if (bn == BigInt.zero) {
                                bn = BigInt.zero;
                            }else {
                                bn = BigInt.one;
                            }
                            break;
                    // default:      assert(!'invalid opcode'); break; // TODO: does this ever occur?
                    }

                    this._stack.pop();
                    this._stack.push(toScriptNumBuffer(bn));
//                    this._stack.push(HEX.decode(bn.toRadixString(16)));
                    break;

                case OpCodes.OP_ADD:
                case OpCodes.OP_SUB:
                case OpCodes.OP_MUL:
                case OpCodes.OP_MOD:
                case OpCodes.OP_DIV:
                case OpCodes.OP_BOOLAND:
                case OpCodes.OP_BOOLOR:
                case OpCodes.OP_NUMEQUAL:
                case OpCodes.OP_NUMEQUALVERIFY:
                case OpCodes.OP_NUMNOTEQUAL:
                case OpCodes.OP_LESSTHAN:
                case OpCodes.OP_GREATERTHAN:
                case OpCodes.OP_LESSTHANOREQUAL:
                case OpCodes.OP_GREATERTHANOREQUAL:
                case OpCodes.OP_MIN:
                case OpCodes.OP_MAX:
                // (x1 x2 -- out)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    bn1 = fromScriptNumBuffer(Uint8List.fromList(stack.peek(index: -2)), fRequireMinimal);
                    bn2 = fromScriptNumBuffer(Uint8List.fromList(stack.peek()), fRequireMinimal);

                    if (bn1 == null){
                        bn1 = BigInt.zero;
                    }

                    if (bn2 == null){
                        bn2 = BigInt.zero;
                    }

                    bn = BigInt.zero;

                    switch (opcodenum) {
                        case OpCodes.OP_ADD:
                            bn = bn1 + bn2;
                            break;

                        case OpCodes.OP_SUB:
                            bn = bn1 - bn2;
                            break;

                        case OpCodes.OP_MUL:
                            bn = bn1 * bn2;
                            break;

                        case OpCodes.OP_DIV:
                        // denominator must not be 0
                            if (bn2 == 0) {
                                this._errStr = 'SCRIPT_ERR_DIV_BY_ZERO';
                                return false;
                            }
                            bn = bn1 ~/ bn2;
                            break;

                        case OpCodes.OP_MOD:
                        // divisor must not be 0
                            if (bn2 == BigInt.zero) {
                                this._errStr = 'SCRIPT_ERR_DIV_BY_ZERO';
                                return false;
                            }
                            //FIXME: Is this re-enabled OP_CODE supposed to work in this fucked-up way !?
                            bn = bn1.abs() % bn2.abs(); //seriously ? I have to convert to abs() to get correct result if bn1 < 0. WTF Bitcoin ?

                            if (bn1.isNegative){
                                bn = -bn; //flip sign to conform to weird bitcoin mod behaviour. WTF!?
                            }
                            break;

                        case OpCodes.OP_BOOLAND:

                            if((bn1.compareTo(BigInt.zero) != 0) && (bn2.compareTo(BigInt.zero) != 0)){
                                bn = BigInt.one;
                            }else{
                                bn = BigInt.zero;
                            }

//                            bn = (bn1 == BigInt.zero && bn2 == BigInt.zero) ? BigInt.zero : BigInt.one;
                            break;
                    // case OpCodes.OP_BOOLOR:        bn = (bn1 !== bnZero || bn2 !== bnZero); break;
                        case OpCodes.OP_BOOLOR:
                            bn = (bn1 != BigInt.zero || bn2 != BigInt.zero) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_NUMEQUAL:      bn = (bn1 === bn2); break;
                        case OpCodes.OP_NUMEQUAL:
                            bn = (bn1 == bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_NUMEQUALVERIFY:    bn = (bn1 === bn2); break;
                        case OpCodes.OP_NUMEQUALVERIFY:
                            bn = (bn1 == bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_NUMNOTEQUAL:     bn = (bn1 !== bn2); break;
                        case OpCodes.OP_NUMNOTEQUAL:
                            bn = (bn1 != bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_LESSTHAN:      bn = (bn1 < bn2); break;
                        case OpCodes.OP_LESSTHAN:
                            bn = (bn1 < bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_GREATERTHAN:     bn = (bn1 > bn2); break;
                        case OpCodes.OP_GREATERTHAN:
                            bn = (bn1 > bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_LESSTHANOREQUAL:   bn = (bn1 <= bn2); break;
                        case OpCodes.OP_LESSTHANOREQUAL:
                            bn = (bn1 <= bn2) ? BigInt.one : BigInt.zero;
                            break;
                    // case OpCodes.OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                        case OpCodes.OP_GREATERTHANOREQUAL:
                            bn = (bn1 >= bn2) ? BigInt.one : BigInt.zero;
                            break;
                        case OpCodes.OP_MIN:
                            bn = (bn1 < bn2) ? bn1 : bn2;
                            break;
                        case OpCodes.OP_MAX:
                            bn = (bn1 > bn2) ? bn1 : bn2;
                            break;
                    // default:           assert(!'invalid opcode'); break; //TODO: does this ever occur?
                    }
                    this._stack.pop();
                    this._stack.pop();
                    this._stack.push(toScriptNumBuffer(bn));

                    if (opcodenum == OpCodes.OP_NUMEQUALVERIFY) {
                        // if (CastToBool(stacktop(-1)))
                        if (castToBool(stack.peek())) {
                            this._stack.pop();
                        } else {
                            this._errStr = 'SCRIPT_ERR_NUMEQUALVERIFY';
                            return false;
                        }
                    }
                    break;

                case OpCodes.OP_WITHIN:
                // (x min max -- out)
                    if (this._stack.length < 3) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    bn1 = fromScriptNumBuffer(Uint8List.fromList(stack.peek(index: -3)), fRequireMinimal);
                    bn2 = fromScriptNumBuffer(Uint8List.fromList(stack.peek(index: -2)), fRequireMinimal);
                    var bn3 = fromScriptNumBuffer(Uint8List.fromList(stack.peek()), fRequireMinimal);
                    fValue = (bn2.compareTo(bn1) <= 0) && (bn1.compareTo(bn3) < 0);
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(fValue ? TRUE : FALSE);
                    break;

            //
            // Crypto
            //
                case OpCodes.OP_RIPEMD160:
                case OpCodes.OP_SHA1:
                case OpCodes.OP_SHA256:
                case OpCodes.OP_HASH160:
                case OpCodes.OP_HASH256:
                // (in -- hash)
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf = stack.peek();
                    // valtype vchHash((opcode === OpCodes.OP_RIPEMD160 ||
                    //                 opcode === OpCodes.OP_SHA1 || opcode === Opcode.OP_HASH160) ? 20 : 32);
                    List<int> bufHash;
                    if (opcodenum == OpCodes.OP_RIPEMD160) {
                        bufHash = ripemd160(buf);
                    } else if (opcodenum == OpCodes.OP_SHA1) {
                        bufHash = sha1(buf);
                    } else if (opcodenum == OpCodes.OP_SHA256) {
                        bufHash = sha256(buf);
                    } else if (opcodenum == OpCodes.OP_HASH160) {
                        bufHash = hash160(buf);
                    } else if (opcodenum == OpCodes.OP_HASH256) {
                        bufHash = sha256Twice(buf);
                    }
                    this._stack.pop();
                    this._stack.push(bufHash);
                    break;

                case OpCodes.OP_CODESEPARATOR:
                // Hash starts after the code separator
                    this._pbegincodehash = this.pc;
                    break;

                case OpCodes.OP_CHECKSIG:
                case OpCodes.OP_CHECKSIGVERIFY:
                // (sig pubkey -- bool)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    bufSig = this._stack.peek(index: -2);
                    bufPubkey = this._stack.peek();

                    if (!checkSignatureEncoding(bufSig, this.flags) || !checkPubkeyEncoding(bufPubkey)) {
                        return false;
                    }

                    // Subset of script starting at the most recent codeseparator
                    SVScript subscript = SVScript.fromChunks(this._script.chunks.sublist(this.pbegincodehash));

                    // Drop the signature, since there's no way for a signature to sign itself
                    var tmpScript = SVScript().add(bufSig);
                    subscript.findAndDelete(tmpScript);

                    try {
                        pubkey = SVPublicKey.fromHex(HEX.encode(bufPubkey), strict: false);
                        sig = SVSignature.fromTxFormat(HEX.encode(bufSig)); //FIXME: Why can't I construct a SVSignature that properly verifies from TxFormat ???
                        sig.publicKey = pubkey;

                        String hash = Sighash().hash(this._tx, sig.nhashtype, this._nin, subscript, this._satoshis, flags: this._flags);
                        var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());
                        fSuccess = sig.verify(reversedHash, HEX.encode(bufSig));
                    } catch (e) {
                        // invalid sig or pubkey
                        fSuccess = false;
                    }

                    if (!fSuccess && (this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL != 0) && bufSig.isNotEmpty) {
                        this._errStr = 'SCRIPT_ERR_NULLFAIL';
                        return false;
                    }

                    this._stack.pop();
                    this._stack.pop();

                    // stack.push_back(fSuccess ? vchTrue : vchFalse);
                    this._stack.push(fSuccess ? TRUE : FALSE);
                    if (opcodenum == OpCodes.OP_CHECKSIGVERIFY) {
                        if (fSuccess) {
                            this._stack.pop();
                        } else {
                            this._errStr = 'SCRIPT_ERR_CHECKSIGVERIFY';
                            return false;
                        }
                    }
                    break;

                case OpCodes.OP_CHECKMULTISIG:
                case OpCodes.OP_CHECKMULTISIGVERIFY:
                // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    var i = 1;
                    if (this._stack.length < i) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    var nKeysCount = fromScriptNumBuffer(Uint8List.fromList(stack.peek(index: -i)), fRequireMinimal).toInt();
//                    var nKeysCount = BigInt.parse(HEX.encode(stack.peek(index: -i)), radix: 16).toInt();
                    // TODO: Keys and opcount are parameterized in client. No magic numbers!
                    if (nKeysCount < 0 || nKeysCount > 20) {
                        this._errStr = 'SCRIPT_ERR_PUBKEY_COUNT';
                        return false;
                    }
                    this._nOpCount += nKeysCount;
                    if (this._nOpCount > 201) {
                        this._errStr = 'SCRIPT_ERR_OP_COUNT';
                        return false;
                    }
                    // int ikey = ++i;
                    var ikey = ++i;
                    i += nKeysCount;

                    // ikey2 is the position of last non-signature item in
                    // the stack. Top stack item = 1. With
                    // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
                    // operation fails.
                    var ikey2 = nKeysCount + 2;

                    if (this._stack.length < i) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    var nSigsCount = fromScriptNumBuffer(Uint8List.fromList(stack.peek(index: -i)), fRequireMinimal).toInt();
//                    var nSigsCount = BigInt.parse(HEX.encode(stack.peek(index: -i)), radix: 16).toInt();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount) {
                        this._errStr = 'SCRIPT_ERR_SIG_COUNT';
                        return false;
                    }
                    // int isig = ++i;
                    var isig = ++i;
                    i += nSigsCount;
                    if (this._stack.length < i) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    // Subset of script starting at the most recent codeseparator
                    subscript = SVScript.fromChunks(this._script.chunks.sublist(this.pbegincodehash));

                    // Drop the signatures, since there's no way for a signature to sign itself
                    for (var k = 0; k < nSigsCount; k++) {
                        bufSig = stack.peek(index: -isig - k);
                        subscript.findAndDelete(SVScript().add(bufSig));
                    }

                    fSuccess = true;
                    while (fSuccess && nSigsCount > 0) {
                        // valtype& vchSig  = stacktop(-isig);
                        bufSig = stack.peek(index: -isig);
                        // valtype& vchPubKey = stacktop(-ikey);
                        bufPubkey = this._stack.peek(index: -ikey);

                        if (!checkSignatureEncoding(bufSig, this.flags) || !this.checkPubkeyEncoding(bufPubkey)) { //FIXME: flags !
                            return false;
                        }

                        var fOk;
                        try {
                            pubkey = SVPublicKey.fromHex(HEX.encode(bufPubkey), strict: false);
                            sig = SVSignature.fromTxFormat(HEX.encode(bufSig)); //FIXME: Why can't I construct a SVSignature that properly verifies from TxFormat ???
                            sig.publicKey = pubkey;
//                            fOk = this._tx.verifySignature(sig, pubkey, this._nin, subscript, this._satoshis, this.flags);
                            String hash = Sighash().hash(this._tx, sig.nhashtype, this._nin, subscript, this._satoshis);
                            var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());
                            fOk = sig.verify(reversedHash, HEX.encode(bufSig));
                        } catch (e) {
                            // invalid sig or pubkey
                            fOk = false;
                        }

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed
                        if (nSigsCount > nKeysCount) {
                            fSuccess = false;
                        }
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        if (!fSuccess && (this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL != 0) && (ikey2 <= 0) && stack
                            .peek()
                            .isNotEmpty) {
                            this._errStr = 'SCRIPT_ERR_NULLFAIL';
                            return false;
                        }

                        if (ikey2 > 0) {
                            ikey2--;
                        }

                        this._stack.pop();
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (this._stack.length < 1) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    if ((this.flags & Interpreter.SCRIPT_VERIFY_NULLDUMMY != 0) && stack
                        .peek()
                        .isNotEmpty) {
                        this._errStr = 'SCRIPT_ERR_SIG_NULLDUMMY';
                        return false;
                    }
                    this._stack.pop();

                    this._stack.push(fSuccess ? TRUE : FALSE);

                    if (opcodenum == OpCodes.OP_CHECKMULTISIGVERIFY) {
                        if (fSuccess) {
                            this._stack.pop();
                        } else {
                            this._errStr = 'SCRIPT_ERR_CHECKMULTISIGVERIFY';
                            return false;
                        }
                    }
                    break;

            //
            // Byte string operations
            //
                case OpCodes.OP_CAT:
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    buf1 = stack.peek(index: -2);
                    buf2 = stack.peek();
                    if (buf1.length + buf2.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
                        this._errStr = 'SCRIPT_ERR_PUSH_SIZE';
                        return false;
                    }
                    this._stack.replaceAt(this._stack.length - 2, buf1 + buf2);
                    this._stack.pop();
                    break;

                case OpCodes.OP_SPLIT:
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }
                    buf1 = stack.peek(index: -2);

                    // Make sure the split point is apropriate.
                    var position = fromScriptNumBuffer(Uint8List.fromList(stack.peek()), fRequireMinimal).toInt();
//                    var position = BigInt.parse(HEX.encode(stack.peek()), radix: 16).toInt();
                    if (position < 0 || position > buf1.length) {
                        this._errStr = 'SCRIPT_ERR_INVALID_SPLIT_RANGE';
                        return false;
                    }

                    // Prepare the results in their own buffer as `data`
                    // will be invalidated.
                    // Copy buffer data, to slice it before
                    List<int> n1 = buf1;

                    // Replace existing stack values by the new values.
                    this._stack.replaceAt(this._stack.length - 2, n1.sublist(0, position));
                    this._stack.replaceAt(this._stack.length - 1, n1.sublist(position));
                    break;

            //
            // Conversion operations
            //
                case OpCodes.OP_NUM2BIN:
                // (in -- out)
                    if (this._stack.length < 2) {
                        this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                        return false;
                    }

                    //FIXME: This is probably wrong!
                    // https://www.bitcoincash.org/spec/may-2018-reenabled-opcodes.html

                    var size = fromScriptNumBuffer(Uint8List.fromList(stack.peek()), fRequireMinimal).toInt();
//                    var size = BigInt.parse(HEX.encode(stack.peek()), radix: 16).toInt();
                    if (size > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
                        this._errStr = 'SCRIPT_ERR_PUSH_SIZE';
                        return false;
                    }

                    this._stack.pop();
                    var rawnum = stack.peek();

                    rawnum = this.minimallyEncode(rawnum);

                    // Try to see if we can fit that number in the number of
                    // byte requested.
                    if ( rawnum.length > size) {
                        // We definitively cannot.
                        this._errStr = 'SCRIPT_ERR_IMPOSSIBLE_ENCODING';
                        return false;
                    }

                    // We already have an element of the right size, we
                    // don't need to do anything.
                    if (rawnum.length == size) {
                        this._stack.replaceAt(this._stack.length - 1, rawnum);
                        break;
                    }

                    var signbit = 0x00;
                    if (rawnum.isNotEmpty) {
                      signbit = rawnum[rawnum.length - 1] & 0x80;
                      rawnum[rawnum.length - 1] &= 0x7f;
                    }

                    var num = List<int>(size);
                    num.fillRange(0, num.length, 0);
                    if (rawnum.isNotEmpty) {
                        num[0] = rawnum[0];
                    }

                    var l = rawnum.length - 1;
                    while (l++ < size - 2) {
                      num[l] = 0x00;
                    }

                    num[l] = signbit;

                    this._stack.splice(this._stack.length - 1, 1, values: num);

                    break;

                case OpCodes.OP_BIN2NUM:
        // (in -- out)
                    if (this._stack.length < 1) {
                      this._errStr = 'SCRIPT_ERR_INVALID_STACK_OPERATION';
                      return false;
                    }

                    buf1 = this._stack.peek();
                    buf2 = this.minimallyEncode(buf1);

                    this._stack.replaceAt(this._stack.length - 1, buf2);

                    // The resulting number must be a valid number.
                    if (!this._isMinimallyEncoded(buf2)) {
                      this._errStr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE';
                      return false;
                    }

                    break;

                default:
                    this._errStr = 'SCRIPT_ERR_BAD_OPCODE';
                    return false;
            }
        }

        return true;
    }

    void _callbackStep(Map<String, int> thisStep) {


    }

    bool checkLockTime(BigInt nLockTime) {

        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if (!((this._tx.nLockTime < Interpreter.LOCKTIME_THRESHOLD && nLockTime < (Interpreter.LOCKTIME_THRESHOLD_BN)) ||
                (this._tx.nLockTime >= Interpreter.LOCKTIME_THRESHOLD && nLockTime >= (Interpreter.LOCKTIME_THRESHOLD_BN)))) {
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nLockTime > BigInt.from(this._tx.nLockTime)) {
            return false;
        }

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (this._tx.inputs[this._nin].isFinal()) {
            return false;
        }

        return true;
    }

    bool checkSequence(BigInt nSequence) {

        // Relative lock times are supported by comparing the passed in operand to
        // the sequence number of the input.
        var txToSequence = this._tx.inputs[this._nin].sequenceNumber;

        // Fail if the transaction's version number is not set high enough to
        // trigger BIP 68 rules.
        if (this._tx.version < 2) {
            return false;
        }

        // Sequence numbers with their most significant bit set are not consensus
        // constrained. Testing that the transaction's sequence number do not have
        // this bit set prevents using this property to get around a
        // CHECKSEQUENCEVERIFY check.
        if (txToSequence & Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG != 0) {
            return false;
        }

        // Mask off any bits that do not have consensus-enforced meaning before
        // doing the integer comparisons
        var nLockTimeMask = Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG | Interpreter.SEQUENCE_LOCKTIME_MASK;
        var txToSequenceMasked = BigInt.from(txToSequence & nLockTimeMask);
        var nSequenceMasked = nSequence & BigInt.from(nLockTimeMask);

        // There are two kinds of nSequence: lock-by-blockheight and
        // lock-by-blocktime, distinguished by whether nSequenceMasked <
        // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script unless the type
        // of nSequenceMasked being tested is the same as the nSequenceMasked in the
        // transaction.
        var SEQUENCE_LOCKTIME_TYPE_FLAG_BN = BigInt.from(Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG);

        if (!((txToSequenceMasked < SEQUENCE_LOCKTIME_TYPE_FLAG_BN && nSequenceMasked < SEQUENCE_LOCKTIME_TYPE_FLAG_BN) ||
            (txToSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG_BN && nSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG_BN))) {
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nSequenceMasked > txToSequenceMasked) {
            return false;
        }
        return true;
    }

    bool checkPubkeyEncoding(List<int> pubkey) {
        if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) != 0 && !SVPublicKey.isValid(HEX.encode(pubkey))) {
            this._errStr = 'SCRIPT_ERR_PUBKEYTYPE';
            return false;
        }
        return true;
    }



}
