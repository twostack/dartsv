import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:hex/hex.dart';

import 'transaction_outpoint.dart';
import 'transaction_signer.dart';

class SignerDto {
  TransactionSigner signer;
  TransactionOutpoint outpoint;

  SignerDto(this.signer, this.outpoint);

  TransactionSigner getSigner() {
    return signer;
  }

  TransactionOutpoint getOutpoint() {
    return outpoint;
  }
}

class TransactionBuilder {
  List<TransactionInput> _inputs = List.empty(growable: true);
  List<TransactionOutput> _outputs = List.empty(growable: true);

  //Map the transactionIds we're spending from, to the corresponding UTXO amount in the output
  Map<String, BigInt> _spendingMap = Map();

  LockingScriptBuilder? _changeScriptBuilder;
  BigInt _changeAmount = BigInt.zero;

  TransactionOutput? _changeOutput;

  int _txVersion = 2;

  final int DEFAULT_FEE_PER_KB = 512; //amount in satoshis

  static final BigInt DUST_AMOUNT = BigInt.from(50); //set a safe dust limit

  /// nlocktime limit to be considered block height rather than a timestamp
  static final NLOCKTIME_BLOCKHEIGHT_LIMIT = 5e8;

  static final DEFAULT_SEQNUMBER = 0xFFFFFFFF;
  static final DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_SEQNUMBER - 1;

  /// Margin of error to allow fees in the vicinity of the expected value but doesn't allow a big difference
  static final BigInt FEE_SECURITY_MARGIN = BigInt.from(50);

  int _feePerKb = 50; //initialize to default


  //FIXME: This does nothing at the moment
  BigInt? _transactionFee;

  bool _changeScriptFlag = false;

  Set<TransactionOption> _transactionOptions = Set<TransactionOption>();

  /// Safe upper bound for change address script size in bytes
  static final int CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
  static final int MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;

  // static final int SCRIPT_MAX_SIZE = 149;

  int _nLockTime = 0;

  Map<String, SignerDto> _signerMap = new Map();

  /**
      utxoMap is expected to have :

      {
      "transactionId" : [String],
      "satoshis", [BigInteger],
      "sequenceNumber", [long],
      "outputIndex", [int],
      "scriptPubKey", [String]
      }
   */
  TransactionBuilder spendFromUtxoMapWithSigner(TransactionSigner signer,
      Map<String, dynamic> utxoMap, UnlockingScriptBuilder? unlocker) {
    String transactionId = utxoMap["transactionId"] as String;

    int outputIndex = utxoMap["outputIndex"] as int;
    int sequenceNumber = TransactionInput.MAX_SEQ_NUMBER;
    if (utxoMap["sequenceNumber"] != null)
        sequenceNumber = utxoMap["sequenceNumber"] as int;

    TransactionOutpoint outpoint = new TransactionOutpoint(
        transactionId,
        outputIndex,
        BigInt.from(utxoMap["satoshis"] as int),
        SVScript.fromBitcoindString(utxoMap["scriptPubKey"] as String));

    String mapKey = "${transactionId}:${outputIndex}";

    _signerMap[mapKey] = SignerDto(signer, outpoint);

    unlocker ??= DefaultUnlockBuilder.fromScript(SVScript());

    var input = TransactionInput(utxoMap["transactionId"] as String, outputIndex,sequenceNumber, scriptBuilder: unlocker);

    _spendingMap[mapKey] = BigInt.from(utxoMap["satoshis"] as int);

    _addInput(input);

    return this;
  }

  TransactionBuilder spendFromUtxoMap(Map<String, dynamic> utxoMap,
      UnlockingScriptBuilder? unlocker) {
    String transactionId = utxoMap["transactionId"] as String;

    int outputIndex = utxoMap["outputIndex"] as int;
    var sequenceNumber = utxoMap["sequenceNumber"] == null ? TransactionInput.MAX_SEQ_NUMBER : utxoMap["sequenceNumber"] as int;

    String mapKey = "${transactionId}:${outputIndex}";

    unlocker ??= DefaultUnlockBuilder.fromScript(SVScript());

    var input = TransactionInput(utxoMap["transactionId"] as String,
        outputIndex, sequenceNumber, scriptBuilder : unlocker);

    _spendingMap[mapKey] = BigInt.from(utxoMap["satoshis"] as int);

    _addInput(input);

    return this;
  }

  TransactionBuilder spendFromTxnWithSigner(TransactionSigner signer,
      Transaction txn,
      int outputIndex,
      int sequenceNumber,
      UnlockingScriptBuilder unlocker) {
    //save the transactionId. This is expensive operation which serialises the Tx.
    String transactionId = txn.id;

    //construct the data to save to signerMap
    var output = txn.outputs[outputIndex];

    var outpoint = TransactionOutpoint(
        transactionId, outputIndex, output.satoshis, output.script);

    String mapKey = "${transactionId}:${outputIndex}";
    _signerMap[mapKey] = SignerDto(signer, outpoint);

    //update the spending transactionInput
    var input = TransactionInput(txn.id, outputIndex, sequenceNumber, scriptBuilder: unlocker);

    _spendingMap[mapKey] = txn.outputs[outputIndex].satoshis;

    _addInput(input);
    return this;
  }

  TransactionBuilder spendFromTxn(Transaction txn, int outputIndex,
      int sequenceNumber, UnlockingScriptBuilder unlocker) {
    TransactionInput input =
    TransactionInput(txn.id, outputIndex, sequenceNumber, scriptBuilder: unlocker);

    String mapKey = "${txn.id}:${outputIndex}";
    _spendingMap[mapKey] = txn.outputs[outputIndex].satoshis;

    _addInput(input);
    return this;
  }

  //TODO: Docs
  TransactionBuilder spendFromOutpointWithSigner(TransactionSigner signer,
      TransactionOutpoint outpoint,
      int sequenceNumber,
      UnlockingScriptBuilder unlocker) {
    String mapKey = "${outpoint.transactionId}:${outpoint.outputIndex}";
    _signerMap[mapKey] = SignerDto(signer, outpoint);

    TransactionInput input = TransactionInput(
        outpoint.transactionId, outpoint.outputIndex, sequenceNumber, scriptBuilder: unlocker);

    _spendingMap[mapKey] = outpoint.satoshis;

    _addInput(input);
    return this;
  }

  //TODO: Docs
  TransactionBuilder spendFromOutpoint(
      TransactionOutpoint outpoint,
      int sequenceNumber,
      UnlockingScriptBuilder unlocker) {

    TransactionInput input = TransactionInput( outpoint.transactionId, outpoint.outputIndex, sequenceNumber, scriptBuilder: unlocker);

    String mapKey = "${outpoint.transactionId}:${outpoint.outputIndex}";
    _spendingMap[mapKey] = outpoint.satoshis;

    _addInput(input);
    return this;
  }

  //TODO: Docs
  TransactionBuilder spendFromOutput(
      String utxoTxnId,
      int outputIndex,
      BigInt amount,
      int sequenceNumber,
      UnlockingScriptBuilder unlocker) {

    TransactionInput input = TransactionInput(utxoTxnId, outputIndex, sequenceNumber, scriptBuilder: unlocker);

    String mapKey = "${utxoTxnId}:${outputIndex}";
    _spendingMap[mapKey] = amount;

    _addInput(input);

    return this;
  }
  
  _addInput(TransactionInput input){
    var existList = _inputs.where((element) => element.prevTxnOutputIndex == input.prevTxnOutputIndex && element.prevTxnId == input.prevTxnId);
    if (existList.length == 0)
      _inputs.add(input);
  }

  TransactionBuilder spendFromOutputWithSigner(TransactionSigner signer,
      String utxoTxnId,
      int outputIndex,
      BigInt amount,
      int sequenceNumber,
      UnlockingScriptBuilder unlocker) {
    var outpoint = TransactionOutpoint(
        utxoTxnId, outputIndex, amount, unlocker.getScriptSig());

    String mapKey = "${outpoint.transactionId}:${outpoint.outputIndex}";
    _signerMap[mapKey] = SignerDto(signer, outpoint);

    TransactionInput input =
    TransactionInput(utxoTxnId, outputIndex, sequenceNumber, scriptBuilder: unlocker);

    _spendingMap[mapKey] = amount;

    _addInput(input);

    return this;
  }


  TransactionBuilder spendToLockBuilder(LockingScriptBuilder locker, BigInt satoshis) {
    int satoshiCompare = satoshis.compareTo(BigInt.zero);
    if (satoshiCompare == -1) //equivalent of satoshis < 0
      throw TransactionException(
          "You can only spend zero or more satoshis in an output");

    SVScript script;
    if (locker == null) {
      throw new TransactionException("LockingScriptBuilder cannot be null");
    } else {
      script = locker.getScriptPubkey();
    }

    TransactionOutput txnOutput = new TransactionOutput(satoshis, script);
    _outputs.add(txnOutput);


    return this;
  }

  /**
   * Spends to a P2PKH recipient
   */
  TransactionBuilder spendToPKH(Address address, BigInt satoshis) {
    var locker = P2PKHLockBuilder.fromAddress(address);
    return spendToLockBuilder(locker, satoshis);
  }

  /**
   * Bitcoin Address Where to send any change (lefover satoshis after fees) to
   * @param changeAddress - Bitcoin Address. Implicitly creates a P2PKH output.
   * @return TransactionBuilder
   */
  TransactionBuilder sendChangeToPKH(Address changeAddress) {
    _changeScriptBuilder = P2PKHLockBuilder.fromAddress(changeAddress);
    return sendChangeToLockBuilder(_changeScriptBuilder!);
  }

  /**
   * A flexible way of dictating how to lock up any change output.
   *
   * @param locker - a LockingScriptBuilder instance
   * @return TransactionBuilder
   */
  TransactionBuilder sendChangeToLockBuilder(LockingScriptBuilder locker) {
    _changeScriptBuilder = locker;
    updateChangeOutput();
    _changeScriptFlag = true;

    return this;
  }

  TransactionBuilder withOption(TransactionOption option){
    _transactionOptions.add(option);
    return this;
  }

  TransactionBuilder withTxVersion(int nVersion){
    _txVersion = nVersion;
    return this;
  }

  TransactionBuilder withFee(BigInt value) {
    _transactionFee = value;

    if (_changeScriptBuilder != null)
      updateChangeOutput();

    return this;
  }

  TransactionBuilder withFeePerKb(int fee) {
    _feePerKb = fee;

    if (_changeScriptBuilder != null) updateChangeOutput();

    return this;
  }

  Transaction build(bool performChecks) {

    //make sure change calculations are in order
    // updateChangeOutput();

    if (performChecks) {
      runTransactionChecks();
    }

    Transaction tx = new Transaction();

    tx.version = _txVersion;

    //add transaction inputs
    tx.addInputs(_inputs);


    if (_changeScriptBuilder != null) {

      //only add change output if there is money left over
      var inOutDiff = calcInputTotals() - calcRecipientTotals();
      if (inOutDiff <= BigInt.zero) {
        _changeOutput = null;
      }else {
        TransactionOutput? changeOutput = getChangeOutput();
        if (changeOutput != null)
          tx.addOutput(changeOutput);
      }
    }

    //add transaction outputs
    tx.addOutputs(_outputs);


    tx.nLockTime = _nLockTime;

    //update inputs with signatures
//        String txId = tx.getTransactionId();
    for (int index = 0; index < _inputs.length; index++) {
      TransactionInput currentInput = _inputs[index];
      currentInput.prevTxnId;

      var result = _signerMap.entries.where((entry) {
        var outpoint = entry.value.outpoint;
        var entryKey = "${outpoint.transactionId}:${outpoint.outputIndex}";
        var currentInputKey =
            "${currentInput.prevTxnId}:${currentInput.prevTxnOutputIndex}";
        return entryKey == currentInputKey;
      }).toList();

      if (result.length > 0) {
        SignerDto dto = result[0].value;
        TransactionOutput utxoToSpend = new TransactionOutput(
            dto.outpoint.satoshis, dto.outpoint.lockingScript);

        //TODO: this side-effect programming where the signer mutates my local variable
        //      still bothers me.
        dto.signer.sign(tx, utxoToSpend, index);
      }
    }

    return tx;
  }

  runTransactionChecks() {
    if (invalidSatoshis()) {
      throw new TransactionException("Invalid quantity of satoshis");
    }

    // if (_changeOutput == null){
    //   throw new TransactionException("No change output was specified");
    // }

    BigInt inOutDiff =  calcInputTotals() - calcRecipientTotals();
    if (inOutDiff < BigInt.zero) {
      if (!_transactionOptions.contains(TransactionOption.DISABLE_MORE_OUTPUT_THAN_INPUT)) {
        throw new TransactionAmountException("Invalid output sum of satoshis");
      }
    } else {
      checkForFeeErrors(getUnspentValue());
    }

    checkForDustErrors();

//TODO: This might be a useful check, but can't be done in Builder
//checkForMissingSignatures();
  }

  checkForDustErrors() {
    if (_transactionOptions.contains(TransactionOption.DISABLE_DUST_OUTPUTS)) {
      return;
    }

    for (TransactionOutput output in _outputs) {
      if (output.satoshis < DUST_AMOUNT ) {
        throw TransactionAmountException(
            "You have outputs with spending values below the dust limit of " +
                DUST_AMOUNT.toString());
      }
    }

    //check for dust on change output
    if (_changeOutput != null && _changeOutput!.satoshis < DUST_AMOUNT && _changeOutput!.satoshis >= BigInt.zero) {
      throw new TransactionAmountException(
          "You have a change output with spending value below the dust limit of " +
              DUST_AMOUNT.toString());
    }
  }

  checkForFeeErrors(BigInt unspent) {
    if (_transactionFee != null && _transactionFee! != unspent) {
      String errorMessage = "Unspent value is " +
          unspent.toRadixString(10) +
          " but specified fee is " +
          _transactionFee!.toRadixString(10);
      throw new TransactionFeeException(errorMessage);
    }

    if (!_transactionOptions.contains(TransactionOption.DISABLE_LARGE_FEES)) {
      BigInt maximumFee = FEE_SECURITY_MARGIN * estimateFee();
      if (unspent > maximumFee) {
        if (!_changeScriptFlag) {
          throw new TransactionFeeException(
              "Fee is too large and no change address was provided");
        }

        throw new TransactionFeeException("expected less than " +
            maximumFee.toString() +
            " but got " +
            unspent.toString());
      }
    }
  }


  /// Set the locktime flag on the transaction to prevent it becoming
  /// spendable before specified date
  ///
  /// [future] - The date in future before which transaction will not be spendable.
  TransactionBuilder lockUntilDate(DateTime future) {
    if (future.millisecondsSinceEpoch < NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw LockTimeException('Block time is set too early');
    }

    for (var input in _inputs) {
      if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
        input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
      }
    }

    _nLockTime = future.millisecondsSinceEpoch;

    return this;
  }

  /// Set the locktime flag on the transaction to prevent it becoming
  /// spendable before specified date
  ///
  /// [timestamp] - The date in future before which transaction will not be spendable.
  TransactionBuilder lockUntilUnixTime(int timestamp) {
    if (timestamp < NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw LockTimeException('Block time is set too early');
    }

    _nLockTime = timestamp;

    return this;
  }

  /// Set the locktime flag on the transaction to prevent it becoming
  /// spendable before specified block height
  ///
  /// [blockHeight] - The block height before which transaction will not be spendable.
  TransactionBuilder lockUntilBlockHeight(int blockHeight) {
    if (blockHeight > NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw LockTimeException('Block height must be less than 500000000');
    }

    if (blockHeight < 0) {
      throw LockTimeException("Block height can't be negative");
    }

    for (var input in _inputs) {
      if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
        input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
      }
    }

    //FIXME: assumption on the length of _nLockTime. Risks indexexception
    _nLockTime = blockHeight;

    return this;
  }


  BigInt getUnspentValue() {
    BigInt inputAmount = calcInputTotals();
    BigInt outputAmount = calcRecipientTotals();
    BigInt unspent = inputAmount - outputAmount;

    if (_changeOutput != null)
      unspent = unspent - _changeOutput!.satoshis;

    return unspent;
  }

  bool invalidSatoshis() {
    for (TransactionOutput output in _outputs) {
      //    if (this._satoshis > MAX_SAFE_INTEGER) {
      if (output.satoshis.compareTo(BigInt.zero) == -1)
        return true;

      //can't spend more than the total moneysupply of Bitcoin
      if (output.satoshis.compareTo(Transaction.MAX_MONEY) == 1)
        return true;
    }

    return false;
  }


  updateChangeOutput() {
    //spent amount equals input amount. No change generated. Return.
    var recipientTotals = calcRecipientTotals();
    var inputTotals = calcInputTotals();
    if ( recipientTotals == inputTotals) return;

    //clear change outputs
    this._changeOutput = null;
    TransactionOutput? output = getChangeOutput(); //this has to preceed getFee() call so we can force an estimate
    this._changeAmount = inputTotals - recipientTotals - getFee(); //calculate change

    output?.satoshis = _changeAmount;
  }

  TransactionOutput? getChangeOutput() {
    if (_changeScriptBuilder == null) return null;

    if (_changeOutput == null ) {
      _changeOutput = TransactionOutput(BigInt.zero, _changeScriptBuilder!.getScriptPubkey());
    }

    return _changeOutput;
  }

  // BigInt calculateChange() {
  //   BigInt inputAmount = calcInputTotals();
  //   BigInt outputAmount = calcRecipientTotals();
  //   BigInt unspent = inputAmount - outputAmount;
  //
  //   return unspent - getFee(); //sub
  // }

  BigInt getFee() {
    if (_transactionFee != null) {
      return _transactionFee!;
    }

    //if no change output set, fees should equal to all the unspent amount
    var fee = calcInputTotals() - calcRecipientTotals();
    if (_changeOutput == null && fee > BigInt.zero) {
      return fee;
    }

    return estimateFee();
  }

  BigInt estimateFee() {
    int size = estimateSize();

    BigInt fee = BigInt.from(((size / 1000 * _feePerKb).ceil()).toInt());

    //if fee is less that 256, set fee at 256 satoshis
    //this is current minimum we set automatically if no explicit fee given
    //FIXME: Make this configurable
    if (fee < BigInt.from(256)) {
      fee = BigInt.from(256) > fee ? fee : BigInt.from(256);
    }

    return fee;
  }


  int estimateSize() {
    int result = MAXIMUM_EXTRA_SIZE;

    for (TransactionInput input in _inputs) {
      var script = input.script ??= SVScript();
      var size = script.buffer.length;
      result += size;
    }

    for (TransactionOutput output in _outputs) {
      result += output.script.buffer.length + 9;
    }

    return result;
  }

  BigInt calcInputTotals() {
    BigInt amount = _spendingMap.values.fold(BigInt.zero,
            (previousValue, currentValue) => previousValue + currentValue);

    return amount;
  }

  BigInt calcRecipientTotals() {
    BigInt recipientAmounts = BigInt.zero;

    //add up destination spends
    for (TransactionOutput output in _outputs) {
      recipientAmounts = recipientAmounts + output.satoshis;
    };

    //add change output
    // if (_changeScriptBuilder != null) {
    //   TransactionOutput? changeOutput = getChangeOutput();
    //   if (changeOutput != null)
    //     recipientAmounts = recipientAmounts + changeOutput.satoshis;
    // }

    return recipientAmounts;
  }
}
