import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:sprintf/sprintf.dart';
import 'package:hex/hex.dart';
import 'dart:convert';

class SighashType {
    static const SIGHASH_ALL = 0x00000001;
    static const SIGHASH_NONE = 0x00000002;
    static const SIGHASH_SINGLE = 0x00000003;
    static const SIGHASH_FORKID = 0x00000040;
    static const SIGHASH_ANYONECANPAY = 0x00000080;
}

class ScriptFlags {

    static const SCRIPT_ENABLE_SIGHASH_FORKID = (1 << 16);

    // Do we accept activate replay protection using a different fork id.
    //
    static const SCRIPT_ENABLE_REPLAY_PROTECTION = (1 << 17);


}

class Sighash {
    String _rawHex;

    static const SIGHASH_SINGLE_BUG = '0000000000000000000000000000000000000000000000000000000000000001';
    static const BITS_64_ON = 'ffffffffffffffff';

    static const _DEFAULT_SIGN_FLAGS = ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID;

    Transaction _txn;
    SVScript _subScript;
    int _sighashType;

    Sighash();

    String hash(Transaction txn, int sighashType, int inputNumber, SVScript subscript, BigInt satoshis, {flags = _DEFAULT_SIGN_FLAGS }) {

        //set a default sighashtype
        if ( sighashType == 0) {
            sighashType = SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID;
        }

        var txnCopy = Transaction.fromHex(txn.serialize(performChecks: false)); //make a copy
        var subscriptCopy = P2PKHScriptSig.fromByteArray(HEX.decode(subscript.toHex())); //make a copy

        if (flags & ScriptFlags.SCRIPT_ENABLE_REPLAY_PROTECTION > 0) {
            // Legacy chain's value for fork id must be of the form 0xffxxxx.
            // By xoring with 0xdead, we ensure that the value will be different
            // from the original one, even if it already starts with 0xff.
            var forkValue = sighashType >> 8;
            var newForkValue = 0xff0000 | (forkValue ^ 0xdead);
            sighashType = (newForkValue << 8) | (sighashType & 0xff);
        }

        if ((sighashType & SighashType.SIGHASH_FORKID == SighashType.SIGHASH_FORKID) &&
            (flags & ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID == ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID)) {
            return HEX.encode(this.sigHashForForkid(txnCopy, sighashType, inputNumber, subscriptCopy, satoshis));
        }

        this._sighashType = sighashType;

        this._txn = _prepareTransaction(txnCopy);

        this._subScript = _prepareSubScript(subscriptCopy);


        //blank out the txn input scripts
        //FIXME: This is redundant. Already taken care of in _prepareTransaction() ?
//        txnCopy.inputs.forEach((input) {
//            input.script = P2PKHScriptSig.fromString("");
//        });

        //setup the input we wish to sign
        txnCopy.inputs[inputNumber].script = this._subScript;



        if ((sighashType & 31) == SighashType.SIGHASH_NONE ||
            (sighashType & 31) == SighashType.SIGHASH_SINGLE) {
            // clear all sequenceNumbers
            var ndx = 0;
            txnCopy.inputs.forEach((elem) {
                if (ndx != inputNumber) {
                    txnCopy.inputs[ndx].sequenceNumber = 0;
                }
                ndx++;
            });
        }

        if ((sighashType & 31) == SighashType.SIGHASH_NONE) {

            txnCopy.outputs.removeWhere((elem) => true); //remove the outputs

        } else if ((sighashType & 31) == SighashType.SIGHASH_SINGLE) {
            // The SIGHASH_SINGLE bug.
            // https://bitcointalk.org/index.php?topic=260595.0
            if (inputNumber >= txnCopy.outputs.length) {
                return SIGHASH_SINGLE_BUG;
            }

            var txout = new TransactionOutput();
            txout.script = txnCopy.outputs[inputNumber].script;              //FIXME: What happens if there are not outputs !?
            txout.satoshis = txnCopy.outputs[inputNumber].satoshis;
            txout.outputIndex = txnCopy.outputs[inputNumber].outputIndex;
            txout.prevTxId = txnCopy.outputs[inputNumber].prevTxId;

            //resize outputs to current size of inputIndex + 1

            var outputCount = inputNumber + 1;
            txnCopy.outputs.removeWhere((elem) => true); //remove all the outputs
            //create new outputs up to inputnumer + 1
            for (var ndx =0; ndx < inputNumber +1; ndx++){
                var tx = new TransactionOutput();
                tx.script = P2PKHScriptSig.fromString("");              //FIXME: What happens if there are no outputs !?
                tx.satoshis = BigInt.parse(BITS_64_ON, radix: 16);
                txnCopy.outputs.add(tx);
            }

            //add back the saved output in the corresponding position of inputIndex
            txnCopy.outputs[inputNumber] = txout; //FIXME : ??? Is this the correct way ?

        }


        if (this._sighashType & SighashType.SIGHASH_ANYONECANPAY > 0) {
            var keepTxn = this._txn.inputs[inputNumber];
            txnCopy.inputs.removeWhere((elem) => true); //delete all inputs
            txnCopy.inputs.add(keepTxn);
        }

        return this.toString();
    }

    SVScript _prepareSubScript(SVScript script) {
        //keep everything after last OP_CODESEPARATOR
        var sub = HEX.decode(script.toHex());
        sub = sub.where((byte) => byte != OpCodes.OP_CODESEPARATOR).toList();
        return SVScript.fromByteArray(Uint8List.fromList(sub));

    }

    //by the time this function is called, all _prepare* scripts should have been run
    List<int> getHash() {
        String txnHex = this._txn.serialize(performChecks: false);
        var revHashtype = HEX
            .decode(this._sighashType.toUnsigned(32).toRadixString(16))
            .reversed
            .toList();

        //my super-complicated method of reversing a hex value while preserving leading zeros in byte positions
        var revMap = revHashtype.map((elem) => elem.toRadixString(16).padLeft(2, "0")).fold("", (prev, elem) => prev + elem).padRight(8, "0");
        txnHex = txnHex + revMap;

        return sha256Twice(HEX.decode(txnHex)).reversed.toList();
    }

    Transaction _prepareTransaction(Transaction tx) {
        //delete all input scripts
        tx.inputs.forEach((input) {
            input.script = P2PKHScriptSig.fromString("");
        });

        return tx;
    }

    @override
    String toString() {
        return HEX.encode(getHash());
    }


    List<int> sigHashForForkid(Transaction txn, int sighashType, int inputNumber, SVScript subscript, BigInt satoshis, {flags = _DEFAULT_SIGN_FLAGS }) {
        uint32LE(int val) => HEX.decode(val.toUnsigned(32).toRadixString(16));

        GetPrevoutHash(Transaction tx) {
            var buffer = List<int>();

            tx.inputs.forEach((input) {
                buffer.addAll(HEX.decode(input.prevTxnId).reversed.toList());
                var ndxArr = sprintf("%08s", [HEX.encode(uint32LE(input.outputIndex))]).replaceAll(" ", "0");
                buffer.addAll(HEX.decode(ndxArr).reversed.toList());
//                buffer.addAll(uint32LE(input.outputIndex));
            });

            return sha256Twice(buffer);
        }

        GetSequenceHash(Transaction tx) {
            var buffer = List<int>();

            tx.inputs.forEach((input) {
                var seqArr = sprintf("%08s", [HEX.encode(uint32LE(input.sequenceNumber))]).replaceAll(" ", "0");
                buffer.addAll(HEX.decode(seqArr).reversed.toList());
//                buffer.addAll(uint32LE(input.sequenceNumber).reversed.toList());
            });

            return sha256Twice(buffer);
        }

        GetOutputsHash(Transaction tx, {int n = -1}) {
            var buffer = List<int>();

            if (n < 0) {
                tx.outputs.forEach((output) {
                    buffer.addAll(output.serialize());
                });
            } else {
                buffer.addAll(tx.outputs[n].serialize());
            }

            return sha256Twice(buffer);
        }

        var hashPrevouts = List<int>(32)..fillRange(0, 32,0);
        var hashSequence = List<int>(32)..fillRange(0, 32,0);
        var hashOutputs = List<int>(32)..fillRange(0, 32,0);

        if (!(sighashType & SighashType.SIGHASH_ANYONECANPAY > 0)) {
            hashPrevouts = GetPrevoutHash(txn);
        }

        if (!(sighashType & SighashType.SIGHASH_ANYONECANPAY > 0) &&
            (sighashType & 31) != SighashType.SIGHASH_SINGLE &&
            (sighashType & 31) != SighashType.SIGHASH_NONE) {
                hashSequence = GetSequenceHash(txn);
        }

        if ((sighashType & 31) != SighashType.SIGHASH_SINGLE && (sighashType & 31) != SighashType.SIGHASH_NONE) {
            hashOutputs = GetOutputsHash(txn);
        } else if ((sighashType & 31) == SighashType.SIGHASH_SINGLE && inputNumber < txn.outputs.length) {
            hashOutputs = GetOutputsHash(txn, n: inputNumber);
        }

        var buffer = List<int>();

        // Version
        var verArr= sprintf("%08s", [HEX.encode(uint32LE(txn.version))]).replaceAll(" ", "0");
        buffer.addAll(HEX.decode(verArr));
//        buffer.addAll(uint32LE(txn.version));

        // Input prevouts/nSequence (none/all, depending on flags)
        buffer.addAll(hashPrevouts);
        buffer.addAll(hashSequence);

        //  outpoint (32-byte hash + 4-byte little endian)
        var input = txn.inputs[inputNumber];
        buffer.addAll(HEX.decode(input.prevTxnId).reversed.toList());
        var ndxArr = sprintf("%08s", [HEX.encode(uint32LE(input.outputIndex))]).replaceAll(" ", "0");
        buffer.addAll(HEX.decode(ndxArr).reversed.toList());

        // scriptCode of the input (serialized as scripts inside CTxOuts)
        buffer.addAll(calcVarInt(subscript.buffer.length));
        buffer.addAll(subscript.buffer);

        // value of the output spent by this input (8-byte little endian)
//        var reversedSats = HEX.decode(satoshis.toRadixString(16)).reversed.toList();
        var reversedSats = HEX.encode(HEX.decode(satoshis.toRadixString(16)).reversed.toList()).padRight(16, "0");
        var satArr = sprintf("%016s", [reversedSats]); //lazy way to get to 8 byte padding
//        satArr = satArr.replaceAll(" ", "0"); // hack around sprintf not padding zeros
//        satArr = utf8.decode(utf8.encode(satArr).reversed.toList()); //reversi!
        buffer.addAll(HEX.decode(reversedSats));

        // nSequence of the input (4-byte little endian)
        var sequenceNumber = input.sequenceNumber;
        var seqArr = sprintf("%08s", [HEX.encode(uint32LE(sequenceNumber))]).replaceAll(" ", "0");
        buffer.addAll(HEX.decode(seqArr).reversed.toList());
//        buffer.addAll(uint32LE(sequenceNumber).reversed.toList());

        // Outputs (none/one/all, depending on flags)
        buffer.addAll(hashOutputs);

        // Locktime
        satArr = sprintf("%08s", [HEX.encode(uint32LE(txn.nLockTime))]); //lazy way to get to 8 byte padding
        satArr = satArr.replaceAll(" ", "0"); // hack around sprintf not padding zeros
        buffer.addAll(HEX.decode(satArr));

        //FIXME: All the code that mangles buffer ops like this is one big fail right now. I can't even...
        // sighashType
        satArr = sprintf("%08s", [HEX.encode(uint32LE((sighashType >> 0).toUnsigned(32)).reversed.toList())]); //lazy way to get to 8 byte padding
        satArr = satArr.replaceAll(" ", "0"); // hack around sprintf not padding zeros
        buffer.addAll(HEX.decode(HEX.encode(uint32LE((sighashType >> 0).toUnsigned(32)).reversed.toList()).padRight(8,"0")));

        var ret = sha256Twice(buffer);
        return ret.reversed.toList();
    }


}
