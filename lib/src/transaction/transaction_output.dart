import 'package:dartsv/src/address.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/P2PKHScriptPubkey.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:hex/hex.dart';
import 'transaction.dart';
import 'package:sprintf/sprintf.dart';

class TransactionOutput {
    Address _recipient;
    BigInt _satoshis = BigInt.zero;
    String _prevTxId;
    int _outputIndex;
    bool _isChangeOutput = false;

    SVScript _script;

    TransactionOutput();

    String get scriptHex {
        return this._script.toHex();
    }

    SVScript get script => _script;

    set script(SVScript script) {
        _script = script;
    }

    Address get recipient => _recipient;

    set recipient(Address address) {
        this._script = P2PKHScriptPubkey(address);
        _recipient = address;
    }

    BigInt get satoshis => _satoshis;

    set satoshis(BigInt value) {
        _satoshis = value;
    }

    String get prevTxId => _prevTxId;

    set prevTxId(String value) {
        _prevTxId = value;
    }

    int get outputIndex => _outputIndex;

    set outputIndex(int value) {
        _outputIndex = value;
    }

    bool get isChangeOutput => _isChangeOutput;

    set isChangeOutput(bool value) {
        _isChangeOutput = value;
    }

    ///Returns true is satoshi amount is outside of valid range
    bool invalidSatoshis() {
        //    if (this._satoshis > MAX_SAFE_INTEGER) {
        if (this._satoshis < BigInt.zero)
            return true;

        if (this._satoshis > Transaction.MAX_MONEY) //yes, there is a finite amount of bitcoin
            return true;

        return false;
    }

    Iterable<int> serialize() {
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


}

