import 'dart:typed_data';

import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:buffer/buffer.dart';


class TransactionInput {
    TransactionOutput _utxo;
    static int UINT_MAX =  0xFFFFFFFF;
    int sequenceNumber;
    bool _isPubkeyHashInput = false;

    TransactionInput(String txId, int outputIndex, SVScript script, BigInt satoshis, int sequenceNumber) {
        this._utxo = TransactionOutput();
        this._utxo.satoshis = satoshis;
        this._utxo.prevTxId = txId;
        this._utxo.outputIndex = outputIndex;
        this._utxo.script = script;
        this.sequenceNumber = sequenceNumber == null ? UINT_MAX - 1 : sequenceNumber;

        this._isPubkeyHashInput = this._utxo.script.isScriptHashOut();
    }

    BigInt get satoshis => output.satoshis;

    set satoshis(BigInt value) {
        output.satoshis = value;
    }

    SVScript get script => output.script;

    set script(SVScript script) {
        this._isPubkeyHashInput = script is P2PKHScriptSig;
        output.script = script;
    }

    int get outputIndex => output.outputIndex;

    set outputIndex(int value) {
        output.outputIndex = value;
    }

    String get prevTxnId => output.prevTxId;

    set prevTxnId(String value) {
        output.prevTxId = value;
    }

    TransactionOutput get output => _utxo;

    set output(TransactionOutput value) {
        _utxo = value;
    }

    Iterable<int> serialize() {
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
    bool isFullySigned() {
        return this._isPubkeyHashInput;
    }

  TransactionInput.fromReader(ByteDataReader reader) {

      this._utxo = TransactionOutput();
      this._utxo.prevTxId = HEX.encode(reader.read(32, copy: true).reversed.toList());
      this._utxo.outputIndex = reader.readUint32(Endian.little);

      var len = readVarIntNum(reader);
      this._utxo.script = SVScript.fromBuffer(reader.read(len, copy: true));

      this.sequenceNumber = reader.readUint32(Endian.little);

      this._isPubkeyHashInput = this._utxo.script.isScriptHashOut();
  }

  Object toObject(){
        return {
            "prevTxId": this.prevTxnId,
            "outputIndex": this.outputIndex,
            "sequenceNumber": this.sequenceNumber,
            "script": this.script.toHex()
        };
  }

  bool isFinal() {
      return this.sequenceNumber == UINT_MAX;
  }


}
