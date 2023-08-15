import 'dart:typed_data';
import 'package:buffer/buffer.dart';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/scriptflags.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';

import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'exceptions.dart';
import 'script/opcodes.dart';

/// [Transaction] signature flags that determine which portions of a [Transaction] the signature in the [TransactionInput] applies to.
///
/// ## Please read
/// [SighashType.SIGHASH_ALL]
///
/// [SighashType.SIGHASH_NONE]
///
/// [SighashType.SIGHASH_SINGLE]
///
/// [SighashType.SIGHASH_ANYONECANPAY]
///
/// [SighashType.SIGHASH_FORKID]
///
class SighashType {
    /// The signature in the [TransactionInput] applies to all the [TransactionInput]s *and all* the [TransactionOutput]s
    static const SIGHASH_ALL = 0x00000001;

    /// The signature in the [TransactionInput] applies *only* to *all* the [TransactionInput]s
    static const SIGHASH_NONE = 0x00000002;

    /// The signature in the [TransactionInput] applies to *all* the
    /// [TransactionInput]s and *only* the corresponding [TransactionOutput] with the *same index* as
    /// the [TransactionInput] containing the signature.
    static const SIGHASH_SINGLE = 0x00000003;

    /// A flag to provide replay-protection after the Bitcoin-Cash hard-fork.
    /// A bitwise-OR e.g. `SIGHASH_FORKID | SIGHASH_ALL`
    /// is required to spend outputs on the BCH and BSV networks
    /// subsequent to the Bitcoin-Cash fork in 2017.
    static const SIGHASH_FORKID = 0x00000040;


    /// This flag is used in combination with any of the *ALL*, *NONE* or *SINGLE* flags.
    ///
    /// `SIGHASH_ALL | SIGHASH_ANYONECANPAY` - Signature applies to *all* [TransactionOutput]s,
    /// but *only* to the [TransactionInput] that the signature is part of.
    ///
    /// `SIGHASH_NONE | SIGHASH_ANYONECANPAY` - Signature applies to *only* the [TransactionInput] that
    /// the signature is part of, and to *none* of the [TransactionOutput]s
    ///
    /// `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` - Signature applies to *only* the [TransactionInput that
    /// the signature is part *AND ONLY* the one corresponding [TransactionOutput] (same index).
    static const SIGHASH_ANYONECANPAY = 0x00000080;

    static const ANYONECANPAY_NONE = 0x00000082;

    static const ANYONECANPAY_SINGLE = 0x00000083;

    static const UNSET = 0x00; // Caution: Using this type in isolation is non-standard. Treated similar to ALL.
}


/// Implements the Signature Hash algorithm.
///
/// Depending on the Sighash flags specified in [SighashType], this class will remove the parts of the transaction
/// that should not be covered by the signature and calculates the hash value to be signed.
///
/// Basically what we do is :
///
/// 1) Strip all the parts of the [Transaction] that should not be covered by the signature
/// 2) Serialize the "stripped" [Transaction]
/// 3) Calculate the double-sha256 of the serialized [Transaction]
///
class Sighash {

    static const _SIGHASH_SINGLE_BUG = '0000000000000000000000000000000000000000000000000000000000000001';
    static const _BITS_64_ON = 'ffffffffffffffff';

    static const _DEFAULT_SIGN_FLAGS = ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID;

    Transaction? _txn;
    SVScript? _subScript;
    int _sighashType = 0;
    Uint8List? _preImage;

    Uint8List? get preImage => _preImage;

  /// Calculates the hash value according to the Sighash flags specified in [sighashType]
    ///
    /// [txn] - The transaction to calculate the signature has for
    ///
    /// [sighashType] - The bitwise combination of [SighashType] flags
    ///
    /// [inputNumber] - The input index in [txn] that the hash applies to
    ///
    /// [subscript] - The portion of [SVScript] in the [TransactionOutput] of Spent [Transaction] (after OP_CODESEPERATOR) that will be covered by the signature
    ///
    /// [flags] - The bitwise combination of [ScriptFlags] related to Sighash. Applies to BSV and BCH only,
    ///           and refers to `SCRIPT_ENABLE_SIGHASH_FORKID` and `SCRIPT_ENABLE_REPLAY_PROTECTION`
    Sighash();

    String hash(Transaction txn, int sighashType, int inputNumber, SVScript subscript, BigInt? satoshis, {flags = _DEFAULT_SIGN_FLAGS }) {

        var txnCopy = Transaction.fromHex(txn.serialize()); //make a copy
        this._txn = txnCopy;
        var subscriptCopy = SVScript.fromHex(subscript.toHex()); //make a copy

        if (flags & ScriptFlags.SCRIPT_ENABLE_REPLAY_PROTECTION > 0) {
            // Legacy chain's value for fork id must be of the form 0xffxxxx.
            // By xoring with 0xdead, we ensure that the value will be different
            // from the original one, even if it already starts with 0xff.
            var forkValue = sighashType >> 8;
            var newForkValue = 0xff0000 | (forkValue ^ 0xdead);
            sighashType = (newForkValue << 8) | (sighashType & 0xff);
        }

        if ((sighashType & SighashType.SIGHASH_FORKID != 0) && (flags & ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID != 0)) {
            return HEX.encode(this._sigHashForForkid(txnCopy, sighashType, inputNumber, subscriptCopy, satoshis));
        }

        this._sighashType = sighashType;

        // For no ForkId sighash, separators need to be removed.
        this._subScript = subscript.removeCodeseparators(); //FIXME: This was removed in my implementation. How did I break things ?

        //blank out the txn input scripts
        txnCopy.inputs.forEach((input) {
            input.script = SVScript.fromString("");
        });


        //setup the input we wish to sign
        var tmpInput = txnCopy.inputs[inputNumber];
        tmpInput = TransactionInput(tmpInput.prevTxnId, tmpInput.prevTxnOutputIndex,tmpInput.sequenceNumber, scriptBuilder: DefaultUnlockBuilder.fromScript(tmpInput.script!));
        tmpInput.script = this._subScript!;
        txnCopy.inputs[inputNumber] = tmpInput;

        txnCopy.serialize();

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
                return _SIGHASH_SINGLE_BUG;
            }

            var txout = new TransactionOutput(txnCopy.outputs[inputNumber].satoshis, txnCopy.outputs[inputNumber].script);

            //resize outputs to current size of inputIndex + 1

            var outputCount = inputNumber + 1;
            txnCopy.outputs.removeWhere((elem) => true); //remove all the outputs
            //create new outputs up to inputnumer + 1
            for (var ndx = 0; ndx < inputNumber + 1; ndx++) {
                var txOutput = new TransactionOutput(BigInt.parse(_BITS_64_ON, radix: 16), SVScript.fromString(""));
                txnCopy.outputs.add(txOutput);
            }

            //add back the saved output in the corresponding position of inputIndex
            txnCopy.outputs[inputNumber] = txout; //FIXME : ??? Is this the correct way ?

        }


        if (this._sighashType & SighashType.SIGHASH_ANYONECANPAY > 0) {
            var keepTxn = this._txn!.inputs[inputNumber];
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
        String txnHex = this._txn!.serialize();

        var writer = ByteDataWriter();
        writer.write(HEX.decode(txnHex));
        writer.writeInt32(this._sighashType, Endian.little);


        _preImage = writer.toBytes();
        print(HEX.encode(_preImage!.toList()));
        return sha256Twice(_preImage!.toList()).reversed.toList();
    }

//    Transaction _prepareTransaction(Transaction tx) {
//        return tx;
//    }

    /// Returns the hexadecimal String of the signature hash
    @override
    String toString() {
        return HEX.encode(getHash());
    }


    List<int> _sigHashForForkid(Transaction txn, int sighashType, int inputNumber, SVScript subscript, BigInt? satoshis, {flags = _DEFAULT_SIGN_FLAGS }) {

        if (satoshis == null){
            throw BadParameterException("For ForkId=0 signatures, satoshis or complete input must be provided");
        }

        var input = txn.inputs[inputNumber];

        List<int> GetPrevoutHash(Transaction tx) {
            var writer = ByteDataWriter();

            tx.inputs.forEach((TransactionInput input) {
                writer.write(HEX.decode(input.prevTxnId).reversed.toList());
                writer.writeUint32(input.prevTxnOutputIndex, Endian.little);
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

        List<int> GetOutputsHash(Transaction tx, { int? n = null}) {
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

        var hashPrevouts = List<int>.filled(32, 0);
        var hashSequence = List<int>.filled(32, 0);
        var hashOutputs = List<int>.filled(32, 0);

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
        writer.writeInt32(txn.version, Endian.little);

        // Input prevouts/nSequence (none/all, depending on flags)
        writer.write(hashPrevouts);
        writer.write(hashSequence);

        //  outpoint (32-byte hash + 4-byte little endian)
        writer.write(HEX
            .decode(input.prevTxnId)
            .reversed
            .toList());
        writer.writeUint32(input.prevTxnOutputIndex, Endian.little);

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
        writer.writeUint32(txn.nLockTime, Endian.little);

        // sighashType
        writer.writeUint32(sighashType >> 0, Endian.little);

        _preImage = writer.toBytes();
        var ret = sha256Twice(_preImage!.toList());
        return ret.reversed.toList();
    }

}
