import 'dart:convert';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';

//import 'package:dartsv/src/script/P2PKHScriptSig.dart';
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
        if (sighashType == 0) {
            sighashType = SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID;
        }

        var txnCopy = Transaction.fromHex(txn.serialize(performChecks: false)); //make a copy
        this._txn = txnCopy;
        var subscriptCopy = SVScript.fromByteArray(HEX.decode(subscript.toHex())); //make a copy

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

        // For no ForkId sighash, separators need to be removed.
        this._subScript = subscript.removeCodeseparators(); //FIXME: This was removed in my implementation. How did I break things ?

        //blank out the txn input scripts
        txnCopy.inputs.forEach((input) {
            input.script = SVScript.fromString("");
        });

//        this._subScript = _prepareSubScript(subscriptCopy);


        //setup the input we wish to sign
//        txcopy.inputs[inputNumber] = new Input(txcopy.inputs[inputNumber]).setScript(subscript)
//        var tmpInput = txnCopy.inputs[inputNumber];
//        tmpInput = TransactionInput(tmpInput.prevTxnId, tmpInput.outputIndex, tmpInput.script, tmpInput.satoshis, tmpInput.sequenceNumber);
//        tmpInput.script = this._subScript;
//        txnCopy.inputs[inputNumber] = tmpInput;
        txnCopy.inputs[inputNumber].script = this._subScript;

//        txnCopy.serialize(performChecks: false);

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
            txout.script = txnCopy.outputs[inputNumber].script; //FIXME: What happens if there are not outputs !?
            txout.satoshis = txnCopy.outputs[inputNumber].satoshis;
            txout.outputIndex = txnCopy.outputs[inputNumber].outputIndex;
            txout.prevTxId = txnCopy.outputs[inputNumber].prevTxId;

            //resize outputs to current size of inputIndex + 1

            var outputCount = inputNumber + 1;
            txnCopy.outputs.removeWhere((elem) => true); //remove all the outputs
            //create new outputs up to inputnumer + 1
            for (var ndx = 0; ndx < inputNumber + 1; ndx++) {
                var tx = new TransactionOutput();
                tx.script = SVScript.fromString(""); //FIXME: What happens if there are no outputs !?
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

    //NOTE: This is broken. It will arbitrarily remove any bytes that match OP_CODESEPARATOR from *any* hex string
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

//    Transaction _prepareTransaction(Transaction tx) {
//        return tx;
//    }

    @override
    String toString() {
        return HEX.encode(getHash());
    }


    List<int> sigHashForForkid(Transaction txn, int sighashType, int inputNumber, SVScript subscript, BigInt satoshis, {flags = _DEFAULT_SIGN_FLAGS }) {

        if (satoshis == null){
            throw BadParameterException("For ForkId=0 signatures, satoshis or complete input must be provided");
        }

        var input = txn.inputs[inputNumber];

        List<int> GetPrevoutHash(Transaction tx) {
            var writer = ByteDataWriter();

            tx.inputs.forEach((TransactionInput input) {
                writer.write(HEX.decode(input.prevTxnId).reversed.toList());
                writer.writeUint32(input.outputIndex, Endian.little);
            });

            var buf = writer.toBytes();
            return sha256Twice(buf.toList());
        }

        List<int> GetSequenceHash(Transaction tx) {
            var writer = ByteDataWriter();

            tx.inputs.forEach((input) {
                writer.writeUint32(input.sequenceNumber, Endian.little);
            });

            var buf = writer.toBytes();
            return sha256Twice(buf.toList());
        }

        List<int> GetOutputsHash(Transaction tx, { int n = null}) {
            var writer = ByteDataWriter();

            if (n == null) {
                tx.outputs.forEach((output) {
                    writer.write(output.serialize(), copy: true);
                });
            } else {
                writer.write(tx.outputs[n].serialize(), copy: true);
            }

            var buf = writer.toBytes();
            return sha256Twice(buf.toList());
        }

        var hashPrevouts = List<int>(32)..fillRange(0, 32, 0);
        var hashSequence = List<int>(32)..fillRange(0, 32, 0);
        var hashOutputs = List<int>(32)..fillRange(0, 32, 0);

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

        ByteDataWriter writer = ByteDataWriter();

        // Version
        writer.writeInt32(txn.version, Endian.big); //FIXME: This *should* be converted to LE, but shows up already in LE over here

        // Input prevouts/nSequence (none/all, depending on flags)
        writer.write(hashPrevouts);
        writer.write(hashSequence);

        //  outpoint (32-byte hash + 4-byte little endian)
        writer.write(HEX
            .decode(input.prevTxnId)
            .reversed
            .toList());
        writer.writeUint32(input.outputIndex, Endian.little);

        // scriptCode of the input (serialized as scripts inside CTxOuts)
        writer.write(varIntWriter(subscript.buffer.length).toList(), copy: true);
        writer.write(subscript.buffer);

        // value of the output spent by this input (8-byte little endian)
        writer.writeUint64(satoshis.toInt(), Endian.little);

        // nSequence of the input (4-byte little endian)
        var sequenceNumber = input.sequenceNumber;
        writer.writeUint32(sequenceNumber, Endian.little);

        // Outputs (none/one/all, depending on flags)
        writer.write(hashOutputs);

        // Locktime
        writer.writeUint32(txn.nLockTime, Endian.big); //FIXME: nLockTime is already LE, conversion TO LE should be required here

        // sighashType
        writer.writeUint32(sighashType >> 0, Endian.little);

        var buf = writer.toBytes();
        var ret = sha256Twice(buf.toList());
        return ret.reversed.toList();
    }

}
