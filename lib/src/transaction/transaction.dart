import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/OpReturnScriptPubkey.dart';
import 'package:dartsv/src/script/P2PKHScriptPubkey.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/signature.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'dart:typed_data';

enum FeeMethod {
    USER_SPECIFIES,
    WALLET_CALCULATES
}

enum TransactionOption {
    DISABLE_ALL,
    DISABLE_MORE_OUTPUT_THAN_INPUT,
    DISABLE_LARGE_FEES,
    DISABLE_DUST_OUTPUTS,
    DISABLE_FULLY_SIGNED

    ///  * `disableAll`: disable all checks
    ///  * `disableLargeFees`: disable checking for fees that are too large
    ///  * `disableIsFullySigned`: disable checking if all inputs are fully signed
    ///  * `disableDustOutputs`: disable checking if there are no outputs that are dust amounts
    ///  * `disableMoreOutputThanInput`: disable checking if the transaction spends more bitcoins than the sum of the input amounts
}

// FIXME: This whole class and how you handle TXNs, inputs and outputs is fucked! Deep refactor needed.
//        You should consider using traits/mixins for Inputs and Outputs to build something CLEAN.
class Transaction {
    String _txnHex = "";
    List<int> _version = HEX.decode("01000000"); //current version number of data structure (4 bytes)
    List<int> _nLockTime = HEX.decode("00000000"); //HEX.decode("FFFFFFFF"); //default to max value. equivalent to "ignore". (4 bytes)
    List<TransactionInput> _txnInputs = List();
    List<TransactionOutput> _txnOutputs = List();
    Address _changeAddress = null;
    Set<TransactionOption> _transactionOptions = Set<TransactionOption>();

    BigInt _fee = null;
    bool _changeScriptFlag = false;

    var CURRENT_VERSION = 1;
    var DEFAULT_NLOCKTIME = 0;
    var MAX_BLOCK_SIZE = 1000000;

// Minimum amount for an output for it not to be considered a dust output
    static final DUST_AMOUNT = BigInt.from(546);

// Margin of error to allow fees in the vecinity of the expected value but doesn't allow a big difference
    static final FEE_SECURITY_MARGIN = BigInt.from(150);

// max amount of satoshis in circulation
    static final MAX_MONEY = BigInt.from(21000000 * 1e8);

// nlocktime limit to be considered block height rather than a timestamp
    static final NLOCKTIME_BLOCKHEIGHT_LIMIT = 5e8;


    static final DEFAULT_SEQNUMBER = 0xFFFFFFFF;
    static final DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_SEQNUMBER - 1;

// Max value for an unsigned 32 bit value
    static final NLOCKTIME_MAX_VALUE = 4294967295;

// Value used for fee estimation (satoshis per kilobyte)
    static const FEE_PER_KB = 1000;

// Safe upper bound for change address script size in bytes
    static final CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
    static final MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;
    static final SCRIPT_MAX_SIZE = 149;

    var _feePerKb = FEE_PER_KB;

    Transaction();

    Transaction.fromHex(String txnHex) {
        this._parseTransactionHex(txnHex);

        this._txnHex = txnHex;
    }

    /// transaction ID
    String get id => HEX.encode(sha256Twice(HEX.decode(this._txnHex)).reversed.toList());


    String get txnHex => _txnHex;

    String serialize({performChecks = true}) {
        if (performChecks)
            _doSerializationChecks();

        return uncheckedSerialize();
    }

    bool invalidSatoshis() {
        return this._txnOutputs.fold(true, (bool valid, TransactionOutput output) => valid && output.invalidSatoshis());
    }


    _doSerializationChecks() {

        if (this.invalidSatoshis()) {
            throw TransactionAmountException("Invalid quantity of satoshis");
        }

        BigInt unspent = this._getUnspentValue();
        if (unspent < BigInt.zero) {
            if (!transactionOptions.contains(TransactionOption.DISABLE_MORE_OUTPUT_THAN_INPUT)) {
                throw TransactionAmountException("Invalid output sum of satoshis");
            }
        } else {
            this._checkForFeeErrors(unspent);
        }

        this._checkForDustErrors();
        this._checkForMissingSignatures();
    }

    void _checkForDustErrors() {
      if (transactionOptions.contains(TransactionOption.DISABLE_DUST_OUTPUTS))
          return;

      for (var output in this._txnOutputs) {
        if (output.satoshis < Transaction.DUST_AMOUNT && !(output.script is OpReturnScriptPubkey)) {
            throw new TransactionAmountException("You have outputs with spending values below the dust limit");
        }
      }
    }

    void _checkForMissingSignatures() {
        if (transactionOptions.contains(TransactionOption.DISABLE_FULLY_SIGNED)) return;

        if (!this.isFullySigned())
            throw new TransactionException("Missing Signatures");

    }


    void _checkForFeeErrors(BigInt unspent) {
        if ((this._fee != null) && (this._fee != unspent)) {
            var errorMessage = "Unspent value is " + unspent.toRadixString(10) + " but specified fee is " + this._fee.toRadixString(10);
            throw new TransactionFeeException(errorMessage);
        }

        if (!transactionOptions.contains(TransactionOption.DISABLE_LARGE_FEES)) {
            var maximumFee = (Transaction.FEE_SECURITY_MARGIN * this._estimateFee());
            if (unspent > maximumFee) {
                if (!this._hasChangeScript()) {
                    throw new TransactionFeeException('Fee is too large and no change address was provided');
                }

                throw new TransactionFeeException('expected less than ' + maximumFee.toString() + ' but got ' + unspent.toString());
            }
        }
    }



    //snarfed method off moneybutton/bsv
    String uncheckedSerialize() {
        List<int> buffer = List<int>();

        //add txn version number
        buffer.addAll(this._version);

        //add all inputs
        var varIntVal = calcVarInt(this._txnInputs.length);
        buffer.addAll(varIntVal);
        this._txnInputs.forEach((input) {
            buffer.addAll(input.serialize());
        });


        //add all outputs
        varIntVal = calcVarInt(this._txnOutputs.length);
        buffer.addAll(varIntVal);
        this._txnOutputs.forEach((output) {
            buffer.addAll(output.serialize());
        });

        //add nLockTime
        buffer.addAll(this._nLockTime);

        return HEX.encode(buffer);
    }

    //returns new buffer pointer
    int _parseTransactionInput(int offset, Uint8List buffer) {
        /*
        36 bytes   previous_output	outpoint	The previous outpoint being spent. See description of outpoint below.
        Varies	script bytes	compactSize uint	The number of bytes in the signature script. Maximum is 10,000 bytes.
        Varies	signature script	char[]	A script-language script which satisfies the conditions placed in the outpoint’s pubkey script. Should only contain data pushes; see the signature script modification warning.
        4	sequence	uint32_t	Sequence number. Default for Bitcoin Core and almost all other programs is 0xffffffff.
         */

        var txnOutput = buffer.sublist(offset, offset + 36); //36 bytes for the previous Transaction Output
        //first 32 bytes == txnID
        var txnId = txnOutput
            .sublist(0, 32)
            .reversed
            .toList(); //txnId from a buffer is BigEndian. Let's flipit.


        //next 4 bytes == output index
        var outIndex = hexToUint32(txnOutput
            .sublist(32, 36)
            .reversed
            .toList());

        offset = offset + 36;
        var firstByte = int.parse(HEX.encode(buffer.sublist(offset, offset + 1)), radix: 16).toUnsigned(8);
        var varIntSize = getBufferOffset(firstByte);
        int numBytes = readVarInt(buffer.sublist(offset, offset + varIntSize))
            .toInt(); //narrow the BigInt in this context because a BigInt bytecount here is rediculous
        offset = offset + varIntSize;

        var sigScript = buffer.sublist(offset, numBytes + offset);
        offset = offset + numBytes;
        var sequence = buffer
            .sublist(offset, offset + 4)
            .reversed
            .toList(); //last 4 bytes

        var uintSeq = hexToUint32(sequence);

        //TODO: Where do I find UTXO amount ?
        this._txnInputs.add(TransactionInput(HEX.encode(txnId), outIndex, HEX.encode(sigScript), BigInt.zero, uintSeq));

        return offset + 4;
    }


    int _parseTransactionOutput(int offset, Uint8List buffer) {
        var satBuf = buffer
            .sublist(offset, offset + 8)
            .reversed
            .toList();
        BigInt satoshis = hexToUint64(satBuf);
        offset = offset + 8;

        //TODO: Factor out this recipe for calculating the varInt number + buffer cursor
        var firstByte = int.parse(HEX.encode(buffer.sublist(offset, offset + 1)), radix: 16).toUnsigned(8);
        var varIntSize = getBufferOffset(firstByte);
        int numBytes = readVarInt(buffer.sublist(offset, offset + varIntSize)).toInt();
        offset = offset + varIntSize;

        var scriptPubKey = buffer.sublist(offset, offset + numBytes);
        var txnOutput = TransactionOutput();
        txnOutput.satoshis = satoshis;
        txnOutput.script = P2PKHScriptPubkey.fromByteArray(scriptPubKey);
        this._txnOutputs.add(txnOutput);

        offset = offset + numBytes;
        return offset;
    }

    void _parseTransactionHex(String txnHex) {
        //first four bytes == txn version number
        var buffer = HEX.decode(txnHex);

        this._version = buffer.sublist(0, 4);
        var offset = 4;
        var firstByte = int.parse(HEX.encode(buffer.sublist(offset, offset + 1)), radix: 16).toUnsigned(8);
        var varIntSize = getBufferOffset(firstByte);
        int txnInCount = readVarInt(buffer.sublist(offset, offset + varIntSize)).toInt();
        offset = offset + varIntSize;

        //iterate over reading txnInCount Transactions starting at the calculated offset
        int ndx = 0;
        while (ndx < txnInCount) {
            offset = _parseTransactionInput(offset, buffer);
            ndx++;
        }
        //process transaction Outputs from this point forwards
        firstByte = int.parse(HEX.encode(buffer.sublist(offset, offset + 1)), radix: 16).toUnsigned(8);
        varIntSize = getBufferOffset(firstByte);
        int txnOutCount = readVarInt(buffer.sublist(offset, offset + varIntSize)).toInt();
        offset = offset + varIntSize;
        ndx = 0;
        while (ndx < txnOutCount) {
            offset = _parseTransactionOutput(offset, buffer);
            ndx++;
        }

        this._nLockTime = buffer.sublist(buffer.length - 4, buffer.length);
    }

    /*
4	    version	uint32_t	Transaction version number; currently version 1 or 2. Programs creating transactions using newer consensus rules may use higher version numbers. Version 2 means that BIP 68 applies.
Varies	tx_in   count	compactSize uint	Number of inputs in this transaction.
Varies	tx_in	txIn	Transaction inputs. See description of txIn below.
Varies	tx_out  count	compactSize uint	Number of outputs in this transaction.
Varies	tx_out	txOut	Transaction outputs. See description of txOut below.
4	    lock_time	uint32_t	A time (Unix epoch time) or block number. See the locktime parsing rules.
         */
    Transaction spendTo(Address recipient, BigInt sats) {
        if (sats <= BigInt.zero) throw new TransactionAmountException('You can only spend a positive amount of satoshis');

        var txnOutput = TransactionOutput();
        txnOutput.recipient = recipient;
        txnOutput.satoshis = sats;
        //see if there are any outputs to join
        //_txnOutputs.addInput(txnInput);

        _txnOutputs.add(txnOutput);

        updateChangeOutput();
        return this;
    }

    Transaction addData(String data) {

        var dataOut = new TransactionOutput();
        dataOut.script = OpReturnScriptPubkey(data);
        dataOut.satoshis = BigInt.zero;

        this._txnOutputs.add(dataOut);

        return this;
    }

    Transaction spendFromInputs(List<TransactionInput> inputs) {
        inputs.forEach((input) => _txnInputs.add(input));

        updateChangeOutput();
        return this;
    }

    Transaction spendFromMap(Map<String, Object> map) {
        //FIXME: More robust validation / error handling needed here.
        if (map['satoshis'] == null || !(map['satoshis'] is BigInt))
            throw UTXOException("An amount to spend is required in BigInt format");

        if (map['txId'] == null)
            throw UTXOException("Transaction ID must be specified");

        if (map['outputIndex'] == null)
            throw UTXOException("An index (vout) to spend from is required");

        if (map['scriptPubKey'] == null)
            throw UTXOException("scriptPubKey from UTXO is required");

        BigInt amountToSpend = map['satoshis'];
        String transactionId = map['txId'];
        int outputIndex = map['outputIndex'];
        String scriptPubKey = map['scriptPubKey'];

        if (inputExists(transactionId, outputIndex)) return this;

        var txnInput = TransactionInput(transactionId, outputIndex, scriptPubKey, amountToSpend, TransactionInput.UINT_MAX);

        _txnInputs.add(txnInput);

        updateChangeOutput();
        return this;
    }

    bool inputExists(String transactionId, int outputIndex) =>
        this._txnInputs
            .where((input) => input.prevTxnId == transactionId && input.outputIndex == outputIndex)
            .isNotEmpty;

    void _removeChangeOutputs() {
        _txnOutputs.removeWhere((elem) => elem.isChangeOutput);
    }

    //FIXME: implementation pending
    bool isFullySigned() {
       /*

  _.each(this.inputs, function (input) {
    if (input.isFullySigned === Input.prototype.isFullySigned) {
      throw new errors.Transaction.UnableToVerifySignature(
        'Unrecognized script kind, or not enough information to execute script.' +
        'This usually happens when creating a transaction from a serialized transaction'
      )
    }
  })
  return _.every(_.map(this.inputs, function (input) {
    return input.isFullySigned()
  }))
        */
       return this._txnInputs.fold(true, (prev, elem) => prev && elem.isFullySigned());
    }

    void updateChangeOutput() {
        if (this._changeAddress == null) return;

//        //this is a sanity check. When parsing external outputs we might not be
//        //correctly setting isChangeOutput
//        //FIXME: ^^^^^^
//        var foundChangeOutput = _txnOutputs.where((elem) => elem.isChangeOutput);
//        if (foundChangeOutput.isEmpty) return;

//        var change = _recalculateChange();
//        if (change < getFee()){
////            _removeChangeOutputs();
////            return ;
//        }

        _removeChangeOutputs();

        if (_nonChangeRecipientTotals() == _inputTotals()) return;

        var txnOutput = getChangeOutput();

        var changeAmount = _recalculateChange();

        //can't spend negative amount of change :/
        if (changeAmount > BigInt.zero) {
            txnOutput.recipient = this._changeAddress;
            txnOutput.satoshis = changeAmount;
            txnOutput.script = P2PKHScriptPubkey(this._changeAddress);
            txnOutput.isChangeOutput = true;
            _txnOutputs.add(txnOutput);
        }
    }

    Transaction sendChangeTo(Address changeAddress) {
        this._changeScriptFlag = true;
        //get fee, and if there is not enough change to cover fee, remove change outputs


        //delete previous change transaction if exists
        this._changeAddress = changeAddress;
        updateChangeOutput(); //side-effect programming FTW :facepalm:
        return this;
    }

    BigInt _unspentValue() => _inputTotals() - _recipientTotals();

    BigInt _recipientTotals() => this._txnOutputs.fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);

    BigInt get outputAmount => this._recipientTotals();
    BigInt get inputAmount => this._inputTotals();

    BigInt _nonChangeRecipientTotals() {
        return this._txnOutputs
            .where((txnOut) => !txnOut.isChangeOutput)
            .fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);
    }

    BigInt _inputTotals() => this._txnInputs.fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);


    BigInt _recalculateChange() {
        var inputAmount = _inputTotals();
        var outputAmount = _nonChangeRecipientTotals();
        var unspent = inputAmount - outputAmount;

        return unspent - getFee();
    }


    Transaction signWith(SVPrivateKey privateKey, {sighashType: 0}) {
        SVSignature sig = SVSignature.fromPrivateKey(privateKey);
        sig.nhashtype = sighashType;

        for (var ndx = 0; ndx < this._txnInputs.length; ndx++) {
            var input = this._txnInputs[ndx];

            //FIXME: This assumes we are spending multiple inputs with the same private key
            //FIXME: This is a test work-around for why I can't sign an unsigned raw txn
            input.output.script = P2PKHScriptPubkey(privateKey.toAddress(networkType: privateKey.networkType));

            var subscript = input.output.script; //pubKey script of the output we're spending
            var sigHash = Sighash();
            var hash = sigHash.hash(this, sighashType, ndx, subscript, input.output.satoshis);

            //FIXME: Revisit this issue surrounding the need to sign a reversed copy of the hash.
            ///      Right now I've factored this out of signature.dart because "coupling" & "seperation of concerns".
            var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());
            sig.sign(reversedHash);

            var txSignature = sig.toTxFormat(); //signed hash with SighashType appended

            //sanity check to assert that we can verify the generated signature using our public key
            var signature = sig.toDER();
            var signerPubkey = privateKey.publicKey.toString();
            SVSignature verifier = SVSignature.fromPublicKey(SVPublicKey.fromHex(signerPubkey));
            bool check = verifier.verify(reversedHash, HEX.encode(signature));

            //if this test fails then something went horribly wrong
            if (check == false)
                throw SignatureException("Generated Signature failed to verify");

            var networkType = privateKey.networkType;
            //update the input script's scriptSig
            input.script = P2PKHScriptSig(txSignature, signerPubkey); //Spend using pubkey associated with privateKey

        }


        // sighash ought to be correct

        //sign the hash of this transaction
        return this;
    }

    Transaction withFee(BigInt value) {
        this._fee = value;
        updateChangeOutput();
        return this;
    }

    Transaction withFeePerKb(int newFee) {
        this._feePerKb = newFee;
        updateChangeOutput();
        return this;
    }


    TransactionOutput getChangeOutput() {
        var outputs = this._txnOutputs.where((elem) => elem.isChangeOutput);

        if (outputs.isEmpty) {
            var out = TransactionOutput();
            out.isChangeOutput = true;
//            this._txnOutputs.add(out);
            return out;
        }

        return outputs.first; //there should be only one

    }

    bool isCoinbase() {
        //if we have a Transaction with one input, and a prevTransactionId of zeroooos, it's a coinbase.
        return (this._txnInputs.length == 1 && this._txnInputs[0].output.prevTxId.replaceAll("0", "").trim() == "");
    }

    bool _hasChangeScript() => this._changeScriptFlag; //{
//        return this._txnOutputs.fold(false, (prev, elem) => prev || elem.isChangeOutput);
    //}

    ///
    ///  [portions ported from moneybutton/bsv]
    ///  Calculates the fee of the transaction.
    ///
    ///  If there's a fixed fee set, return that.
    ///
    ///  If there is no change output set, the fee is the
    ///  total value of the outputs minus inputs. Note that
    ///  a serialized transaction only specifies the value
    ///  of its outputs. (The value of inputs are recorded
    ///  in the previous transaction outputs being spent.)
    ///  This method therefore raises a "MissingPreviousOutput"
    ///  error when called on a serialized transaction.
    ///
    ///  If there's no fee set and no change address,
    ///  estimate the fee based on size.
    BigInt getFee() {
        if (this.isCoinbase()) {
            return BigInt.zero;
        }

        if (this._fee != null)
            return this._fee;

        // if no change output is set, fees should equal all the unspent amount
        if (!this._hasChangeScript()) {
            return this._getUnspentValue();
        }
//
        return this._estimateFee();
    }

    /// Estimates fee from serialized transaction size in bytes.
    BigInt _getUnspentValue() {
        BigInt inputAmount = _inputTotals();
        BigInt outputAmount = this._txnOutputs.fold(BigInt.zero, (BigInt prev, TransactionOutput elem) => prev + elem.satoshis);

        return inputAmount - outputAmount;
    }

    BigInt _estimateFee() {
//        if (this._fee != null)
//            return this._fee;

        var estimatedSize = this._estimateSize();
        BigInt available = this._getUnspentValue();

        var fee = BigInt.from((estimatedSize / 1000 * this._feePerKb).ceil());
        if (available > fee) {
            estimatedSize += CHANGE_OUTPUT_MAX_SIZE;
        }
        fee = BigInt.from((estimatedSize / 1000 * this._feePerKb).ceil());

        return fee;
    }

    int _estimateSize() {
        var result = MAXIMUM_EXTRA_SIZE;
        this._txnInputs.forEach((input) {
            result += SCRIPT_MAX_SIZE; //TODO: we're only spending P2PKH atm.
//            result += input.output.scriptHex.length; //TODO: CHECK !!! What about other transaction bits ?
        });

        this._txnOutputs.forEach((output) {
            result += HEX
                .decode(output.script.toHex())
                .length + 9; // <---- HOW DO WE CALCULATE SCRIPT FROM JUST AN ADDRESS !? AND LENGTH ???
        });

        return result;
    }

    //FIXME: This is horribly borked
    List<SVSignature> getSignatures(SVPrivateKey privateKey) {
        return List<SVSignature>();
    }

    void sortInputs(List<TransactionInput> txns) {
        txns.sort((lhs, rhs) {
            var txnIdComparison = lhs.prevTxnId.compareTo(rhs.prevTxnId);

            if (txnIdComparison != 0) {
                //we use the prevTxnId to sort
                return txnIdComparison;
            } else {
                //txnIds can't be used (probably 'cause there's only one)
                return lhs.outputIndex - rhs.outputIndex;
            }
        });
    }

    void sortOutputs(List<TransactionOutput> txns) {
        txns.sort((lhs, rhs) {
            var satoshiComparison = lhs.satoshis - rhs.satoshis;
            if (satoshiComparison != BigInt.zero)
                return satoshiComparison > BigInt.zero ? 1 : -1;
            else
                return lhs.scriptHex.compareTo(rhs.scriptHex);
        });
    }

    /// Sort inputs and outputs according to Bip69
    ///
    Transaction sort() {
        sortInputs(this._txnInputs);
        sortOutputs(this._txnOutputs);
        return this;
    }


    int get version {
        return hexToInt32(this._version);
    }

    int get nLockTime {
        return int.parse(HEX.encode(this._nLockTime), radix: 16);
    }

    List<TransactionInput> get inputs {
        return this._txnInputs;
    }

    List<TransactionOutput> get outputs {
        return this._txnOutputs;
    }

    Set<TransactionOption> get transactionOptions => _transactionOptions;

    String verify() {

      // Basic checks that don't depend on any context
      if (this._txnInputs.isEmpty) {
        return 'transaction txins empty';
      }

      if (this._txnOutputs.isEmpty) {
        return 'transaction txouts empty';
      }

      // Check for negative or overflow output values
      var valueoutbn = BigInt.zero;
      var ndx = 0;
      for (var txout in this._txnOutputs) {

        if (txout.invalidSatoshis()) {
          return 'transaction txout $ndx satoshis is invalid';
        }
        if (txout.satoshis > Transaction.MAX_MONEY) {
          return 'transaction txout ${ndx} greater than MAX_MONEY';
        }
        valueoutbn = valueoutbn + txout.satoshis;
        if (valueoutbn > Transaction.MAX_MONEY) {
          return 'transaction txout ${ndx} total output greater than MAX_MONEY';
        }
      }

      // Size limits
      if (this.serialize(performChecks: false).length > MAX_BLOCK_SIZE) {
        return 'transaction over the maximum block size';
      }

      // Check for duplicate inputs
      var txinmap = {};
      for (var i = 0; i < this.inputs.length; i++) {
        var txin = this.inputs[i];

        var inputid = txin.prevTxnId + ":" + txin.outputIndex.toString();
        if (txinmap[inputid]) {
          return 'transaction input ' + i.toString() + ' duplicate input';
        }
        txinmap[inputid] = true;
      }

      var isCoinbase = this.isCoinbase();
      if (isCoinbase) {
        var buf = this.inputs[0].script.buffer;
        if (buf.length < 2 || buf.length > 100) {
          return 'coinbase transaction script size invalid';
        }
      } else {
        for (var i = 0; i < this.inputs.length; i++) {
          if (this.inputs[i] == null) {
            return 'transaction input ' + i.toString() + ' has null input';
          }
        }
      }
      return "";
    }

    //returns either DateTime or int (blockHeight)
    //I really don't like type overloading like this.
    //FIXME: Figure out how to use Type System to force consumer of this method to think about the return value. e.g. scala.Option
    getLockTime() {
        var timestamp = int.parse(HEX.encode(this._nLockTime), radix: 16);
        if (timestamp < 500000000) {
            return timestamp;
        }else {
            var date = DateTime.fromMillisecondsSinceEpoch(timestamp);
            return date;
        }
    }

    lockUntilDate(DateTime future) {

        if (future.millisecondsSinceEpoch < NLOCKTIME_BLOCKHEIGHT_LIMIT)
            throw new LockTimeException("Block time is set too early");

        for (var input in this._txnInputs) {
            if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
                input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
            }
        }

        this._nLockTime = HEX.decode(future.millisecondsSinceEpoch.toRadixString(16));
    }

    lockUntilUnixTime(int timestamp) {
        if (timestamp < NLOCKTIME_BLOCKHEIGHT_LIMIT)
            throw new LockTimeException("Block time is set too early");

        this._nLockTime = HEX.decode(timestamp.toRadixString(16));
    }

    lockUntilBlockHeight(int blockHeight) {
        if (blockHeight > NLOCKTIME_BLOCKHEIGHT_LIMIT)
            throw new LockTimeException("Block height must be less than 500000000");

        if (blockHeight < 0)
            throw new LockTimeException("Block height can't be negative");


        for (var input in this._txnInputs) {
            if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
                input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
            }
        }

        //FIXME: assumption on the length of _nLockTime. Risks indexexception
        this._nLockTime.fillRange(0, 3, 0);
        this._nLockTime.setRange(1, 4, HEX.decode(blockHeight.toRadixString(16))) ;
    }

    bool verifySignature(sig, pubkey, int nin, SVScript subscript, BigInt satoshis, int flags) {
        return false;
    }

}
