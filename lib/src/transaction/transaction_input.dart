import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptPubkey.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:buffer/buffer.dart';

import 'transaction.dart';


//class P2PKHInput extends TransactionInput with ScriptSig{
//
//    P2PKHInput(String txId, int outputIndex, SVScript script, BigInt satoshis, int seqNumber) :
//            super(txId, outputIndex, script, satoshis, seqNumber);
//
//    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey){
//        return P2PKHScriptSig(txSignature.toTxFormat(), signerPubkey.toString()); //Spend using pubkey associated with privateKey
//    }
//
//}

abstract class UnlockingScriptBuilder {
    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey);
}

abstract class LockingScriptBuilder {
    SVScript getScriptPubkey();
}

class P2PKHLockBuilder extends LockingScriptBuilder {
    Address _address;

    P2PKHLockBuilder(this._address);

    SVScript getScriptPubkey(){
        return P2PKHScriptPubkey(_address);
    }
}

class P2PKHUnlockBuilder extends UnlockingScriptBuilder{

    SVScript getScriptSig(SVSignature txSignature, SVPublicKey signerPubkey){
        return P2PKHScriptSig(txSignature.toTxFormat(), signerPubkey.toString()); //Spend using pubkey associated with privateKey
    }
}



/// Class that represents the "input" to a transaction.
///
/// In bitcoin the transaction inputs of a new transaction are formed
/// from what was the output of the previous transaction that we are
/// "spending" from. In this way a chain of transactions are formed,
/// and because each transaction contains a signature in the input,
/// a chain of digital signatures representing change of ownership
/// from one transaction to the next is also captured.
///
class TransactionInput {
    TransactionOutput _prevTxnOutput;

    /// Maximum size an unsigned int can be. Used as value of [sequenceNumber] when we
    /// want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
    static int UINT_MAX =  0xFFFFFFFF;
    bool _isPubkeyHashInput = false;

    int _sequenceNumber;

    /// Constructs a new transaction input
    ///
    /// [txId] - The *id* of the transaction we are "spending from"
    ///
    /// [outputIndex] - The index of the transaction output (UTXO) in the transaction identified by [txId]
    ///
    /// [script] - The bitcoin script from the transaction output (UTXO) in the transaction identified by [txId]
    ///
    /// [satoshis] - The amount of satoshis in the transaction output (UTXO) in the transaction identified by [txId]
    ///
    /// [seqNumber] - The sequenceNumber is supposed to allow a transaction to be updated before being
    /// broadcast to the network. At least, that was the original purpose. At present this is only used to
    /// indicate whether nLockTime should be honored or ignored. Set this value to [UINT_MAX] to indicate
    /// that transaction's [Transaction.nLockTime] should be ignored.
    TransactionInput(String txId, int outputIndex, SVScript script, BigInt satoshis, int seqNumber) {
        _prevTxnOutput = TransactionOutput();
        _prevTxnOutput.satoshis = satoshis;
        _prevTxnOutput.transactionId = txId;
        _prevTxnOutput.outputIndex = outputIndex;
        _prevTxnOutput.script = script;
        _sequenceNumber = seqNumber == null ? UINT_MAX - 1 : seqNumber;

        _isPubkeyHashInput = _prevTxnOutput.script.isScriptHashOut();
    }


    /// Constructs a new Transaction input from a ByteDataReader that
    /// has been initialized with the raw transaction input data.
    ///
    /// This method is useful when iteratively reading the transaction
    /// inputs in a raw transaction, which is also how it is currently
    /// being used.
    TransactionInput.fromReader(ByteDataReader reader) {

        _prevTxnOutput = TransactionOutput();
        _prevTxnOutput.transactionId = HEX.encode(reader.read(32, copy: true).reversed.toList());
        _prevTxnOutput.outputIndex = reader.readUint32(Endian.little);

        var len = readVarIntNum(reader);
        _prevTxnOutput.script = SVScript.fromBuffer(reader.read(len, copy: true));

        _sequenceNumber = reader.readUint32(Endian.little);

        _isPubkeyHashInput = _prevTxnOutput.script.isScriptHashOut();
    }

    ///Returns a buffer containing the serialized bytearray for this TransactionInput
    List<int> serialize() {
        var writer = ByteDataWriter();


        writer.write(HEX.decode(_prevTxnOutput.transactionId).reversed.toList(), copy: true);

        writer.writeUint32(_prevTxnOutput.outputIndex, Endian.little);
        var scriptHex = HEX.decode(_prevTxnOutput.script.toHex());

        writer.write(varIntWriter(scriptHex.length).toList(), copy: true);
        writer.write(scriptHex, copy: true);

        writer.writeUint32(sequenceNumber, Endian.little);

        return writer.toBytes().toList();
    }

    //This method only makes sense when working with P2PKH.
    //The world on BSV is much larger than that.
    /// This is used by the Transaction during serialization checks.
    /// It is only used in the context of P2PKH transaction types and
    /// will likely be deprecated in future.
    bool isFullySigned() {
        return _isPubkeyHashInput;
    }

    /// Returns the Transaction input as structured data to make
    /// working with JSON serializers easier.
    Map<String, dynamic> toObject(){
        return {
            'prevTxId': _prevTxnOutput.transactionId,
            'outputIndex': _prevTxnOutput.outputIndex,
            'sequenceNumber': sequenceNumber,
            'script': _prevTxnOutput.script.toHex()
        };
    }

    /// Returns *true* if the sequence number has reached it's maximum
    /// limit and can no longer be updated.
    bool isFinal() {
        return sequenceNumber == UINT_MAX;
    }


    void sign(UnlockingScriptBuilder sigBuilder, Transaction tx, SVPrivateKey privateKey, {sighashType = 0}){


        //FIXME: This is a test work-around for why I can't sign an unsigned raw txn
        //FIXME: This assumes we're signing P2PKH

        var subscript = prevTxnOutput.script; //pubKey script of the output we're spending
        var inputIndex = tx.inputs.indexOf(this);
        var hash = Sighash().hash(tx, sighashType, inputIndex, subscript, prevTxnOutput.satoshis);

        //FIXME: Revisit this issue surrounding the need to sign a reversed copy of the hash.
        ///      Right now I've factored this out of signature.dart because 'coupling' & 'seperation of concerns'.
        var reversedHash = HEX.encode(HEX
            .decode(hash)
            .reversed
            .toList());

        // generate a signature for the input
        var sig = SVSignature.fromPrivateKey(privateKey);
        sig.nhashtype = sighashType;
        sig.sign(reversedHash);

        var signerPubkey = privateKey.publicKey;

        //update the input script's scriptSig
        script = sigBuilder.getScriptSig(sig, signerPubkey);

    }

    /// Returns the number of satoshis this input is spending.
    BigInt get satoshis => prevTxnOutput.satoshis;

    /// Sets the number of satoshis this input is spending.
    ///
    /// *NOTE:* A transaction input *must* spend all the satoshis from a UTXO;
    /// change [TransactionOutput]s must be generated as needed, and the difference
    /// between satoshis "consumed" by and input and those "locked" by the input's
    /// corresponding output goes to the miner as a fee reward.
    set satoshis(BigInt value) {
        _prevTxnOutput.satoshis = value;
    }

    /// Returns the script from the parent transaction's output (UTXO)
    SVScript get script => _prevTxnOutput.script;

    /// Set the script that represents the parent transaction's output (UTXO)
    set script(SVScript script) {
        _isPubkeyHashInput = script is P2PKHScriptSig;
        _prevTxnOutput.script = script;
    }

    /// Returns the index value of the transaction output (UTXO) that this input is spending from.
    int get prevTxnOutputIndex => _prevTxnOutput.outputIndex;

    /// Sets the index value of the transaction output (UTXO) that this input is spending from.
    set prevTxnOutputIndex(int value) {
        _prevTxnOutput.outputIndex = value;
    }

    /// Returns the transaction Id of the transaction that this input is spending from
    String get prevTxnId => _prevTxnOutput.transactionId;

    /// Sets the transaction Id of the transaction that this input is spending from
    set prevTxnId(String value) {
        _prevTxnOutput.transactionId = value;
    }

    /// Returns the complete transaction output (UTXO) of the transaction we are spending from
    TransactionOutput get prevTxnOutput => _prevTxnOutput;

    /// Sets the transaction output (UTXO) of the transaction we are spending from
    set prevTxnOutput(TransactionOutput value) {
        _prevTxnOutput = value;
    }


    /// [sequenceNumber] - The sequenceNumber is supposed to allow a transaction to be updated before being
    /// broadcast to the network. At least, that was the original purpose. At present this is only used to
    /// indicate whether nLockTime should be honored or ignored. Set this value to [UINT_MAX] to indicate
    /// that transaction's [Transaction.nLockTime] should be ignored.
    int get sequenceNumber => _sequenceNumber;

    void set sequenceNumber(int seqNumber) {
        _sequenceNumber = seqNumber;
    }


}
