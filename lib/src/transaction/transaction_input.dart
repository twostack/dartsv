import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:dartsv/src/transaction/unlocking_script_builder.dart';
import 'package:hex/hex.dart';
import 'package:buffer/buffer.dart';

import 'transaction.dart';

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

    UnlockingScriptBuilder scriptBuilder;

    /// Maximum size an unsigned int can be. Used as value of [sequenceNumber] when we
    /// want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
    static int UINT_MAX =  0xFFFFFFFF;
    bool _isPubkeyHashInput = false;

    int _sequenceNumber;

    //SVSignature _signature;

    SVScript _scriptSig;

    int _prevTxnOutputIndex;

    String _prevTxnId;

    BigInt _spendingAmount;

    /// Constructs a new transaction input
    ///
    /// [txId] - The *id* of the transaction we are "spending from"
    ///
    /// [outputIndex] - The index of the transaction output (UTXO) in the transaction identified by [txId]
    ///
    /// [script] - The "Unlocking Script" also knows as the ScriptSig [txId]
    ///
    /// [seqNumber] - The sequenceNumber is supposed to allow a transaction to be updated before being
    /// broadcast to the network. At least, that was the original purpose. At present this is only used to
    /// indicate whether nLockTime should be honored or ignored. Set this value to [UINT_MAX] to indicate
    /// that transaction's [Transaction.nLockTime] should be ignored.
    TransactionInput(String txId, int outputIndex, SVScript script, BigInt satoshis, int seqNumber) {
        _prevTxnId = txId;
        _prevTxnOutputIndex = outputIndex;
        _scriptSig = script;
        _sequenceNumber = seqNumber ??= UINT_MAX - 1;
        _spendingAmount = satoshis;

        _isPubkeyHashInput = _scriptSig.isScriptHashOut();
    }


    /// Constructs a new Transaction input from a ByteDataReader that
    /// has been initialized with the raw transaction input data.
    ///
    /// This method is useful when iteratively reading the transaction
    /// inputs in a raw transaction, which is also how it is currently
    /// being used.
    TransactionInput.fromReader(ByteDataReader reader) {

        _prevTxnId = HEX.encode(reader.read(32, copy: true).reversed.toList());
        _prevTxnOutputIndex = reader.readUint32(Endian.little);

        var len = readVarIntNum(reader);
        _scriptSig = SVScript.fromBuffer(reader.read(len, copy: true));

        _sequenceNumber = reader.readUint32(Endian.little);

        _isPubkeyHashInput = _scriptSig.isScriptHashOut();
    }

    ///Returns a buffer containing the serialized bytearray for this TransactionInput
    List<int> serialize() {
        var writer = ByteDataWriter();


        writer.write(HEX.decode(_prevTxnId).reversed.toList(), copy: true);

        writer.writeUint32(_prevTxnOutputIndex, Endian.little);
        var scriptHex = HEX.decode(_scriptSig.toHex());

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
            'prevTxId': _prevTxnId,
            'outputIndex': _prevTxnOutputIndex,
            'sequenceNumber': sequenceNumber,
            'script': _scriptSig.toHex()
        };
    }

    /// Returns *true* if the sequence number has reached it's maximum
    /// limit and can no longer be updated.
    bool isFinal() {
        return sequenceNumber == UINT_MAX;
    }

    /// Returns the number of satoshis this input is spending.
    BigInt get satoshis => _spendingAmount;

    /// Sets the number of satoshis this input is spending.
    ///
    /// *NOTE:* A transaction input *must* spend all the satoshis from a UTXO;
    /// change [TransactionOutput]s must be generated as needed, and the difference
    /// between satoshis "consumed" by and input and those "locked" by the
    /// spending transaction's outputs goes to the miner as a fee reward.
    set satoshis(BigInt value) {
        _spendingAmount = value;
    }

    /// Returns the scriptSig (Input Script / Unlocking Script)
    SVScript get script => _scriptSig; //FIXME: scriptBuilder needs to parse as well

    /// Set the script that represents the parent transaction's output (UTXO)
    set script(SVScript script) {
        _scriptSig = script;
    }

    /// Returns the index value of the transaction output (UTXO) that this input is spending from.
    int get prevTxnOutputIndex => _prevTxnOutputIndex;

    /// Sets the index value of the transaction output (UTXO) that this input is spending from.
    set prevTxnOutputIndex(int value) {
        _prevTxnOutputIndex = value;
    }

    /// Returns the transaction Id of the transaction that this input is spending from
    String get prevTxnId => _prevTxnId;

    /// Sets the transaction Id of the transaction that this input is spending from
    set prevTxnId(String value) {
        _prevTxnId = value;
    }

    /// Returns the signature associated with this TransactionInput
    ///
    /// This property will only hold a value *after* the [sign()] method has been called
//    SVSignature get signature => _signature;

    /// [sequenceNumber] - The sequenceNumber is supposed to allow a transaction to be updated before being
    /// broadcast to the network. At least, that was the original purpose. At present this is only used to
    /// indicate whether nLockTime should be honored or ignored. Set this value to [UINT_MAX] to indicate
    /// that transaction's [Transaction.nLockTime] should be ignored.
    int get sequenceNumber => _sequenceNumber;

    void set sequenceNumber(int seqNumber) {
        _sequenceNumber = seqNumber;
    }


}
