
import 'package:buffer/buffer.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/varint.dart';
import 'transaction.dart';

/// Class that represents the output (UTXO) of a transaction.
///
/// When creating new transactions, the outputs can be :
///
/// 1) Locked up for another recipient to spend
/// 2) Locked up for ourselves to spend
/// 3) Represented as a "data" transaction by using `OP_FALSE OP_RETURN <data>` in the script
/// 4) Represents any arbitrary bitcoin script on the BSV network after the Genesis restoration
/// in February 2020.
///
class TransactionOutput {
    BigInt _satoshis = BigInt.zero;
    SVScript _script = SVScript();

    TransactionOutput( BigInt amount, SVScript scriptPubKey ){
        _satoshis = amount;
        _script = scriptPubKey;
    }

    /// Constructs a new Transaction output from a ByteDataReader that
    /// has been initialized with the raw transaction output data.
    ///
    /// This method is useful when iteratively reading the transaction
    /// outputs in a raw transaction, which is also how it is currently
    /// being used.
    TransactionOutput.fromReader(ByteDataReader reader) {

        var buffer = reader.read(8);
        this.satoshis = castToBigInt(buffer, false, nMaxNumSize: 8);
        var size = readVarIntNum(reader);
        if (size != 0) {
            _script = SVScript.fromBuffer(reader.read(size, copy: true));
        }
    }

    ///Returns true is satoshi amount if outside of valid range
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
        ByteDataWriter writer = new ByteDataWriter();

        var satsBuffer = writeInt64LE(satoshis);
        writer.write(satsBuffer);

        //write the locking script
        List<int> scriptBytes = script.buffer;
        VarInt varInt = VarInt.fromInt(scriptBytes.length);
        List<int> varIntBytes = varInt.encode();
        writer.write(varIntBytes);

        writer.write(scriptBytes);
        return writer.toBytes();

    }


    /// Returns the Transaction output as structured data to make
    /// working with JSON serializers easier.
    Map<String, dynamic> toObject() {
        return {
            "satoshis": this._satoshis.toInt(),
            "script": _script.toHex()
        };
    }

    /// Returns the output script in it's raw hexadecimal form
    String get scriptHex {
        return _script.toHex();
    }

    /// Returns the output script as a [SVScript] instance
    SVScript get script => _script;

    /// Sets the output script to the provided value
    set script(SVScript script) {
        _script = SVScript.fromHex(script.toHex()); //take a copy
    }

    /// Returns the number of satoshis the output is sending
    BigInt get satoshis => _satoshis;

    /// Sets the number of satoshis the output is sending
    set satoshis(BigInt value) {
        _satoshis = value;
    }

    /// Convenience property to check if this output has been made unspendable
    /// using either an OP_RETURN or "OP_FALSE OP_RETURN" in first positions of
    /// the script.
    ///
    ///
    bool get isDataOut {
        var scriptChunks = _script.chunks;
        if (scriptChunks.isNotEmpty && scriptChunks[0].opcodenum == OpCodes.OP_FALSE){
            //safe data out
           return scriptChunks.length >= 2 && scriptChunks[1].opcodenum == OpCodes.OP_RETURN;
        }else if (scriptChunks[0].opcodenum == OpCodes.OP_RETURN){
           //older unsafe data output
            return true;
        }

        return false;
    }

    /// Returns the current instance of LockingScriptBuilder in use by this instance
    // LockingScriptBuilder get scriptBuilder => DefaultLockBuilder();

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

