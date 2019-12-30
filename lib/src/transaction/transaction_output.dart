import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptPubkey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:hex/hex.dart';
import 'transaction.dart';
import 'package:sprintf/sprintf.dart';

/// Class that represents the output (UTXO) of a transaction.
///
/// When creating new transactions, the outputs are can be :
///
/// 1) Locked up for another recipient to spend
/// 2) Locked up for ourselves to spend
/// 3) Represented as a "data" transaction by using `OP_FALSE OP_RETURN <data>` in the script
/// 4) Represent any arbitrary bitcoin script on the BSV network after the Genesis restoration
/// in February 2020.
///
class TransactionOutput {
    Address _recipient;
    BigInt _satoshis = BigInt.zero;
    String _transactionId;
    int _outputIndex;
    bool _isChangeOutput = false;

    SVScript _script;

    /// The default constructor. Initializes a "clean slate" output.
    TransactionOutput();


    /// Constructs a new Transaction output from a ByteDataReader that
    /// has been initialized with the raw transaction output data.
    ///
    /// This method is useful when iteratively reading the transaction
    /// outputs in a raw transaction, which is also how it is currently
    /// being used.
    TransactionOutput.fromReader(ByteDataReader reader) {
        this.satoshis = BigInt.from(reader.readUint64(Endian.little));
        var size = readVarIntNum(reader);
        if (size != 0) {
            this._script = SVScript.fromBuffer(reader.read(size, copy: true));
        } else {
            this._script = SVScript.fromBuffer(Uint8List(0));
        }
    }

    ///Returns true is satoshi amount is outside of valid range
    ///
    /// See [Transaction.MAX_MONEY]
    bool invalidSatoshis() {
        //    if (this._satoshis > MAX_SAFE_INTEGER) {
        if (this._satoshis < BigInt.zero)
            return true;

        if (this._satoshis > Transaction.MAX_MONEY) //yes, there is a finite amount of bitcoin
            return true;

        return false;
    }

    /// Returns a byte array containing the raw transaction output
    List<int> serialize() {
        List<int> buffer = List<int>();

        //add value in satoshis - 8 bytes BigInt
        var satArr = sprintf("%016s", [this._satoshis.abs().toRadixString(16)]); //lazy way to get to 8 byte padding
        satArr = satArr.replaceAll(" ", "0"); // hack around sprintf not padding zeros
        buffer.addAll(HEX
            .decode(satArr)
            .reversed
            .toList());

        //add scriptPubKey size - varInt
        var scriptHex = HEX.decode(this.script.toHex());
        var varIntVal = calcVarInt(scriptHex.length);
        buffer.addAll(varIntVal);

        //add scriptPubKey hex
        buffer.addAll(scriptHex);

        return buffer;
    }


    /// Returns the Transaction output as structured data to make
    /// working with JSON serializers easier.
    Map<String, dynamic> toObject() {
        return {
            "satoshis": this._satoshis.toInt(),
            "script": this.script.toHex()
        };
    }

    /// Returns the output script in it's raw hexadecimal form
    String get scriptHex {
        return this._script.toHex();
    }

    /// Returns the output script as a [SVScript] instance
    SVScript get script => _script;

    /// Sets the output script to the provided value
    set script(SVScript script) {
        _script = script;
    }

    /// Returns the [Address] of the recipient in the case of a
    /// P2PKH output. This is only useful for generating "change outputs".
    Address get recipient => _recipient;

    /// Sets the [Address] of the recipient in the case of a
    /// P2PKH output. This is only useful for generating "change outputs".
    set recipient(Address address) {
        this._script = P2PKHScriptPubkey(address);
        _recipient = address;
    }

    /// Returns the number of satoshis the output is sending
    BigInt get satoshis => _satoshis;

    /// Sets the number of satoshis the output is sending
    set satoshis(BigInt value) {
        _satoshis = value;
    }

    /// Returns the transactionId of the transaction this output belongs to
    String get transactionId => _transactionId;


    /// Sets the transactionId of the transaction this output belongs to
    set transactionId(String value) {
        _transactionId = value;
    }

    /// Returns the index of the (UTXO) in the transaction this output belongs to
    int get outputIndex => _outputIndex;

    /// sets the index of the (UTXO) in the transaction this output belongs to
    set outputIndex(int value) {
        _outputIndex = value;
    }

    /// Returns true if this output is meant to generate change back
    /// the person creating the transaction this output will belong to.
    bool get isChangeOutput => _isChangeOutput;

    /// Set to true if this output is meant to generate change back
    /// the person creating the transaction this output will belong to.
    set isChangeOutput(bool value) {
        _isChangeOutput = value;
    }

//FIXME: Swing back to this leaner implementation based on ByteDataWriter()
//    List<int> serialize2(){
//        var writer = ByteDataWriter();
//
//        writer.writeUint64(this._satoshis.toInt(), Endian.little);
//
//        var scriptHex = HEX.decode(this.script.toHex());
//        writer.write(varIntWriter(scriptHex.length).toList(), copy: true);
//
//        writer.write(this.script.buffer);
//
//        return writer.toBytes().toList();
//    }


}

