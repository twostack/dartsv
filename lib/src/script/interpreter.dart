import 'dart:collection';

import 'package:dartsv/dartsv.dart';


class Stack {
    Queue<String> _queue = new Queue<String>();

    void push(String item) {
        _queue.addLast(item);
    }

    int get length => _queue.length;

    void removeAll() {
        this._queue.clear();
    }

    Stack slice() {
        return this;
    }

    String peek() {
        return _queue.last;
    }

    String pop() {
        return _queue.removeLast();
    }
}

class Interpreter {

    static final MAX_SCRIPT_ELEMENT_SIZE = 520;
    static final MAXIMUM_ELEMENT_SIZE = 4;

    static final LOCKTIME_THRESHOLD = 500000000;
    static final LOCKTIME_THRESHOLD_BN = BigInt.from(LOCKTIME_THRESHOLD);

// flags taken from bitcoind
// bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    static final SCRIPT_VERIFY_NONE = 0;

// Evaluate P2SH subscripts (softfork safe, BIP16).
    static final SCRIPT_VERIFY_P2SH = (1 << 0);

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

    Stack get altstack => _altStack;

    int get pc => _pc;

    int get pbegincodehash => _pbegincodehash;

    int get nOpCount => 0;

    List get vfExec => _vfExec; //???
    String get errstr => _errStr;

    int get flags => _flags;

    bool verifyScript(SVScript scriptSig, SVScript scriptPubkey, {Transaction tx = null, int nin = 0, int flags = 0, BigInt satoshis}) {
        if (tx == null) {
            tx = new Transaction();
        }


        // If FORKID is enabled, we also ensure strict encoding.
        if (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID == 0) {
            flags |= Interpreter.SCRIPT_VERIFY_STRICTENC;

            // If FORKID is enabled, we need the input amount.
            if (satoshis == BigInt.zero) {
                throw ScriptException('internal error - need satoshis to verify FORKID transactions');
            }
        }


        this._script = scriptSig;
        this._tx = tx;
        this._nin = nin;
        this._flags = flags;
        this._satoshis = satoshis;

        var stackCopy;

        if ((flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.isPushOnly()) {
            this._errStr = 'SCRIPT_ERR_SIG_PUSHONLY';
            return false;
        };

        // evaluate scriptSig
        if (!this.evaluate()) {
            return false;
        }

        if (flags & Interpreter.SCRIPT_VERIFY_P2SH != 0) {
            stackCopy = this.stack.slice();
        }

        var stack = this.stack;
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

        if (this.stack.length == 0) {
            this._errStr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT';
            return false;
        }

        String buf = this.stack.peek(); //[this.stack.length - 1];
        if (!_castToBool(buf)) {
            this._errStr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK';
            return false;
        }

        // Additional validation for spend-to-script-hash transactions:
        if ((flags & Interpreter.SCRIPT_VERIFY_P2SH == 0) && scriptPubkey.isScriptHashOut()) {
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
            var redeemScript = SVScript(redeemScriptSerialized);
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

            if (!_castToBool(stackCopy.peek())) {
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
// TODO: Do a proper port of the Script Interpreter O_O
//
    static checkSignatureEncoding(String buf, int flags) {
        var sig;
        var errStr;

        // Empty signature. Not strictly DER encoded, but allowed to provide a
        // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
        if (buf.isEmpty) {
            return true;
        }

        if ((flags & (Interpreter.SCRIPT_VERIFY_DERSIG | Interpreter.SCRIPT_VERIFY_LOW_S | Interpreter.SCRIPT_VERIFY_STRICTENC)) != 0 &&
            !SVSignature.isTxDER(buf)) {
            errStr = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT';
            return false;
        } else if ((flags & Interpreter.SCRIPT_VERIFY_LOW_S) != 0) {
            sig = SVSignature.fromTxFormat(buf);
            if (!sig.hasLowS()) {
                errStr = 'SCRIPT_ERR_SIG_DER_HIGH_S';
                return false;
            }
        } else if ((flags & Interpreter.SCRIPT_VERIFY_STRICTENC) != 0) {
            sig = SVSignature.fromTxFormat(buf);
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

    void clearStacks() {
        this._stack.removeAll();
        this._altStack.removeAll();
    }

    bool evaluate() {
        return false;
    }

    void initialize() {}

    void set(Map map) {
        this._script = map["script"];
        this._tx = map["tx"];
        this._nin = map["nin"];
        this._flags = map["flags"];
        this._satoshis = map["satoshis"];
    }

    bool _castToBool(String buf) {
        return false;
    }


}
