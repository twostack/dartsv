import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';


class TransactionInput {
    TransactionOutput _utxo;
    static int UINT_MAX =  0xFFFFFFFF;
    int sequenceNumber;
    bool _isPubkeyHashInput = false;

    TransactionInput(String txId, int outputIndex, String script, BigInt satoshis, int sequenceNumber) {
        this._utxo = TransactionOutput();
        this._utxo.satoshis = satoshis;
        this._utxo.prevTxId = txId;
        this._utxo.outputIndex = outputIndex;
        this._utxo.script = SVScript.fromHex(script);
        this.sequenceNumber = sequenceNumber == 0 ? UINT_MAX - 1 : sequenceNumber;

        this._isPubkeyHashInput = this._utxo.script is P2PKHScriptSig;
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
        List<int> buffer = List<int>();

        //txid - 32 Bytes
        buffer.addAll(HEX
            .decode(this.prevTxnId)
            .reversed
            .toList());

        //vout - 4 bytes index
        var vout = sprintf("%08x", [this.outputIndex]);
        buffer.addAll(HEX
            .decode(vout)
            .reversed
            .toList());

        //scriptSig Size - varInt
        var scriptHex = HEX.decode(this.script.toHex());
        var varIntVal = calcVarInt(scriptHex.length);
        buffer.addAll(varIntVal);

        //scriptSig
        buffer.addAll(scriptHex);

        //sequence number = Oxffffffff - 4 bytes
        var seq = sprintf("%08x", [this.sequenceNumber]);
        buffer.addAll(HEX
            .decode(seq)
            .reversed
            .toList());

        return buffer;
    }

    bool isFullySigned() {
        return this._isPubkeyHashInput;
    }


}
