import 'dart:typed_data';

import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:buffer/buffer.dart';


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
    TransactionOutput _utxo;

    /// Maximum size an unsigned int can be. Used as value of [sequenceNumber] when we
    /// want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
    static int UINT_MAX =  0xFFFFFFFF;
    bool _isPubkeyHashInput = false;

    /// See the [TransactionInput()] constructor.
    int sequenceNumber;

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
    /// [sequenceNumber] - The sequenceNumber is supposed to allow a transaction to be updated before being
    /// broadcast to the network. At least, that was the original purpose. At present this is only used to
    /// indicate whether nLockTime should be honored or ignored. Set this value to [UINT_MAX] to indicate
    /// that transaction's [Transaction.nLockTime] should be ignored.
    TransactionInput(String txId, int outputIndex, SVScript script, BigInt satoshis, int sequenceNumber) {
        this._utxo = TransactionOutput();
        this._utxo.satoshis = satoshis;
        this._utxo.transactionId = txId;
        this._utxo.outputIndex = outputIndex;
        this._utxo.script = script;
        this.sequenceNumber = sequenceNumber == null ? UINT_MAX - 1 : sequenceNumber;

        this._isPubkeyHashInput = this._utxo.script.isScriptHashOut();
    }


    /// Constructs a new Transaction input from a ByteDataReader that
    /// has been initialized with the raw transaction input data.
    ///
    /// This method is useful when iteratively reading the transaction
    /// inputs in a raw transaction, which is also how it is currently
    /// being used.
    TransactionInput.fromReader(ByteDataReader reader) {

        this._utxo = TransactionOutput();
        this._utxo.transactionId = HEX.encode(reader.read(32, copy: true).reversed.toList());
        this._utxo.outputIndex = reader.readUint32(Endian.little);

        var len = readVarIntNum(reader);
        this._utxo.script = SVScript.fromBuffer(reader.read(len, copy: true));

        this.sequenceNumber = reader.readUint32(Endian.little);

        this._isPubkeyHashInput = this._utxo.script.isScriptHashOut();
    }

    ///Returns a buffer containing the serialized bytearray for this TransactionInput
    List<int> serialize() {
        ByteDataWriter writer = ByteDataWriter();


        writer.write(HEX.decode(this.prevTxnId).reversed.toList(), copy: true);

        writer.writeUint32(this.output.outputIndex, Endian.little);
        var scriptHex = HEX.decode(this.script.toHex());

        writer.write(varIntWriter(scriptHex.length).toList(), copy: true);
        writer.write(scriptHex, copy: true);

        writer.writeUint32(this.sequenceNumber, Endian.little);

        return writer.toBytes().toList();
    }

    //This method only makes sense when working with P2PKH.
    //The world on BSV is much larger than that.
    /// This is used by the Transaction during serialization checks.
    /// It is only used in the context of P2PKH transaction types and
    /// will likely be deprecated in future.
    bool isFullySigned() {
        return this._isPubkeyHashInput;
    }

    /// Returns the Transaction input as structured data to make
    /// working with JSON serializers easier.
    Map<String, dynamic> toObject(){
        return {
            "prevTxId": this.prevTxnId,
            "outputIndex": this.outputIndex,
            "sequenceNumber": this.sequenceNumber,
            "script": this.script.toHex()
        };
    }

    /// Returns *true* if the sequence number has reached it's maximum
    /// limit and can no longer be updated.
    bool isFinal() {
        return this.sequenceNumber == UINT_MAX;
    }

    /// Returns the number of satoshis this input is spending.
    BigInt get satoshis => output.satoshis;

    /// Sets the number of satoshis this input is spending.
    ///
    /// *NOTE:* A transaction input *must* spend all the satoshis from a UTXO;
    /// change [TransactionOutput]s must be generated as needed, and the difference
    /// between satoshis "consumed" by and input and those "locked" by the input's
    /// corresponding output goes to the miner as a fee reward.
    set satoshis(BigInt value) {
        output.satoshis = value;
    }

    /// Returns the script from the parent transaction's output (UTXO)
    SVScript get script => output.script;

    /// Set the script that represents the parent transaction's output (UTXO)
    set script(SVScript script) {
        this._isPubkeyHashInput = script is P2PKHScriptSig;
        output.script = script;
    }

    /// Returns the index value of the transaction output (UTXO) that this input is spending from.
    int get outputIndex => output.outputIndex;

    /// Sets the index value of the transaction output (UTXO) that this input is spending from.
    set outputIndex(int value) {
        output.outputIndex = value;
    }

    /// Returns the transaction Id of the transaction that this input is spending from
    String get prevTxnId => output.transactionId;

    /// Sets the transaction Id of the transaction that this input is spending from
    set prevTxnId(String value) {
        output.transactionId = value;
    }

    /// Returns the complete transaction output (UTXO) of the transaction we are spending from
    TransactionOutput get output => _utxo;

    /// Sets the transaction output (UTXO) of the transaction we are spending from
    set output(TransactionOutput value) {
        _utxo = value;
    }



}
