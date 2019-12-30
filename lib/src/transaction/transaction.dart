import 'dart:collection';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/script/OpReturnScriptPubkey.dart';
import 'package:dartsv/src/script/P2PKHScriptPubkey.dart';
import 'package:dartsv/src/script/P2PKHScriptSig.dart';
import 'package:dartsv/src/signature.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:sprintf/sprintf.dart';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';

import '../exceptions.dart';

enum FeeMethod {
    USER_SPECIFIES,
    WALLET_CALCULATES
}

/// When serializing the transaction to hexadecimal it is possible
/// to selectively disable some checks. See [serialize()]
enum TransactionOption {
    ///  Disables all checks
    DISABLE_ALL,

    ///  Disables checking if the transaction spends more bitcoins than the sum of the input amounts
    DISABLE_MORE_OUTPUT_THAN_INPUT,

    ///  Disables checking for fees that are too large
    DISABLE_LARGE_FEES,

    ///  Disables checking if there are no outputs that are dust amounts
    DISABLE_DUST_OUTPUTS,

    ///  Disables checking if all inputs are fully signed
    DISABLE_FULLY_SIGNED

}

/// Transactions are at the heart of this library. It is the primary means by which we
/// interact with the Bitcoin network.
///
/// A [Transaction] will have one or more [TransactionInput]s that it is spending from
/// and one or more [TransactionOutputs] which represent either the sending of coins
/// to a recipient or the creation of "data"-only output.
///
///
/// The raw hex transaction has the following layout:
///
/// `4 bytes`  - Transaction version number; currently version 1 or 2.
/// Programs creating transactions using newer consensus rules may use higher version numbers.
/// Version 2 means that BIP 68 applies.
///
/// `compactSize uint` - Number of inputs in this transaction.
///
/// `VarByteArray` - Transaction inputs.
///
/// `compactSize uint` - Number of outputs in this transaction.
///
/// `VarByteArray` - Transaction outputs.
///
/// `4 bytes` - A time (Unix epoch time) or block number. See the [nLockTime] parsing rules.
///
class Transaction {
    String _txnHex = "";
    int _version = 1;
    int _nLockTime = 0;
    List<TransactionInput> _txnInputs = List();
    List<TransactionOutput> _txnOutputs = List();
    Address _changeAddress = null;
    Set<TransactionOption> _transactionOptions = Set<TransactionOption>();


    static final SHA256Digest _sha256Digest = SHA256Digest();
    ECDSASigner _dsaSigner = new ECDSASigner(null, HMac(_sha256Digest, 64));
    ECDomainParameters _domainParams = new ECDomainParameters('secp256k1');

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

    /// Default constructor. Start empty, use the builder pattern to
    /// build a transaction.
    ///
    /// E.g.
    /// ```
    /// var testTransaction = Transaction()
    ///     .spendFromMap({
    ///     'txId': testPrevTx,
    ///     'outputIndex': 0,
    ///     'scriptPubKey': testScript,
    ///     'satoshis': testAmount })
    ///     .spendTo(Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc'), testAmount - BigInt.from(10000));
    /// ```
    Transaction();

    /// Creates a new Transaction instance from a JSON or MAP object.
    ///
    /// ### Expected JSON/Map Format
    /// ```
    ///    {
    ///      "hash":"a6f7b4284fb753eab9b554283c4fe1f1d7e143e6cf3b975d0376d7c08ba4cdf5",
    ///      "version":1,
    ///      "inputs":[
    ///        {
    ///          "prevTxId":"0000000000000000000000000000000000000000000000000000000000000000",
    ///          "outputIndex":4294967295,
    ///          "sequenceNumber":4294967295,
    ///          "script":"03e45201062f503253482f"
    ///        }
    ///      ],
    ///      "outputs":[
    ///        {
    ///          "satoshis":5001000000,
    ///          "script":"76a914ee9a7590f91e04832054f0645bbf243c9fac8e2288ac"
    ///        },
    ///        {
    ///          "satoshis":0,
    ///          "script":"4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac"
    ///        },
    ///        {
    ///          "satoshis":0,
    ///          "script":"2458e99e66e2b90bd8b2a0e2bfcce91e1f09ee7621d95e9a728ca2372d45df3ded00000000"
    ///        }
    ///      ],
    ///      "nLockTime":0
    ///    },
    /// ```
    Transaction.fromJSONMap(LinkedHashMap<String, dynamic> map){
        this._version = map["version"];
        this._nLockTime = map["nLockTime"];
        (map["inputs"] as List).forEach((input) {
            this._txnInputs.add(
                TransactionInput(input["prevTxId"], input["outputIndex"], SVScript.fromHex(input["script"]), BigInt.zero, input["sequenceNumber"]));
        });

        (map["outputs"] as List).forEach((output) {
            var txOut = TransactionOutput();
            txOut.satoshis = BigInt.from(output["satoshis"]);
            txOut.script = SVScript.fromHex(output["script"]);
            this._txnOutputs.add(txOut);
        });
    }

    /// Constructs a new transaction instance from the raw hexadecimal string.
    Transaction.fromHex(String txnHex) {
        this._parseTransactionHex(txnHex);

        this._txnHex = txnHex;
    }

    /// Constructs a new transaction from a ByteDataReader which has been
    /// initialized with the raw hex data containing a complete transaction.
    Transaction.fromBufferReader(ByteDataReader reader){
        _fromBufferReader(reader);
    }

    /// Renders this transaction as a Map/Object. See [fromJSONMap()] for example format.
    Map<String, dynamic> toObject() {
        return {
            "hash": this.id,
            "version": this._version,
            "inputs": this._txnInputs.map((input) => input.toObject()).toList(),
            "outputs": this._txnOutputs.map((output) => output.toObject()).toList(),
            "nLockTime": this._nLockTime
        };
    }

    /// Returns the transaction ID.
    ///
    /// The transaction ID is the double-sha256 of the raw (hexadecimal) transaction.
    String get id => HEX.encode(sha256Twice(HEX.decode(this.serialize(performChecks: false))).reversed.toList());

    // transaction Hash - FIXME: I thought 'id' should be equal to 'hash' ? VALIDATE !
    /// Returns the double-sha256 of the raw (hexadecimal) transaction
    List<int> get hash => sha256Twice(HEX.decode(this.serialize(performChecks: false)));


    /// Serialize the transaction object to it's raw hexadecimal representation, ready to be
    /// broadcast to the network, or to be passed to a peer.
    ///
    /// [performChecks] - By default checks are performed as described in [TransactionOption].
    /// To disable those checks set to false.
    ///
    /// Returns the raw transaction as a hexadecimal string.
    String serialize({performChecks = true}) {
        if (performChecks)
            _doSerializationChecks();

        return uncheckedSerialize();
    }


    /// Returns the raw transaction as a hexadecimal string, skipping all checks.
    String uncheckedSerialize() {
        ByteDataWriter writer = ByteDataWriter();

        // set the transaction version
        writer.writeInt32(this.version, Endian.little);

        // set the number of inputs
        writer.write(varintBufNum(this.inputs.length));

        // write the inputs
        this.inputs.forEach((input) {
            writer.write(input.serialize());
        });

        //set the number of outputs to come
        writer.write(varintBufNum(this.outputs.length));

        // write the outputs
        this.outputs.forEach((output) {
            writer.write(output.serialize());
        });

        // write the locktime
        writer.writeUint32(this.nLockTime, Endian.little);
        return HEX.encode(writer.toBytes().toList());
    }

    ///
    ///
    /// *Builder pattern*
    ///
    ///
    Transaction spendTo(Address recipient, BigInt sats) {
        if (sats <= BigInt.zero) throw new TransactionAmountException('You can only spend a positive amount of satoshis');

        var txnOutput = TransactionOutput();
        txnOutput.recipient = recipient;
        txnOutput.satoshis = sats;
        //see if there are any outputs to join
        //_txnOutputs.addInput(txnInput);

        _txnOutputs.add(txnOutput);

        _updateChangeOutput();
        return this;
    }

    Transaction addInput(TransactionInput input) {
        this._txnInputs.add(input);
        this._updateChangeOutput();
        return this;
    }

    Transaction addOutput(TransactionOutput txOutput) {
        this.outputs.add(txOutput);
        this._updateChangeOutput();
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

        _updateChangeOutput();
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

        //sometimes scriptPubKey from the test harness is HEX encoded
        Uint8List script;
        if (BigInt.tryParse(scriptPubKey, radix: 16) != null) {
            script = SVScript
                .fromHex(scriptPubKey)
                .buffer;
        } else {
            script = SVScript
                .fromString(scriptPubKey)
                .buffer;
        }

        if (_inputExists(transactionId, outputIndex)) return this;

        var txnInput = TransactionInput(transactionId, outputIndex, SVScript.fromBuffer(script), amountToSpend, TransactionInput.UINT_MAX);

        _txnInputs.add(txnInput);

        _updateChangeOutput();
        return this;
    }


    Transaction sendChangeTo(Address changeAddress) {
        this._changeScriptFlag = true;
        //get fee, and if there is not enough change to cover fee, remove change outputs


        //delete previous change transaction if exists
        this._changeAddress = changeAddress;
        _updateChangeOutput();
        return this;
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
            var reversedHash = HEX.encode(HEX
                .decode(hash)
                .reversed
                .toList());
            sig.sign(reversedHash);

            var txSignature = sig.toTxFormat(); //signed hash with SighashType appended

            //sanity check to assert that we can verify the generated signature using our public key
//            var signature = sig.toDER();
            var signerPubkey = privateKey.publicKey.toString();
//            SVSignature verifier = SVSignature.fromPublicKey(SVPublicKey.fromHex(signerPubkey));
//            SVSignature verifier = SVSignature.fromPublicKey(SVPublicKey.fromHex(signerPubkey));
//            bool check = verifier.verify(reversedHash, HEX.encode(signature));

            //if this test fails then something went horribly wrong
//            if (check == false)
//                throw SignatureException("Generated Signature failed to verify");

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
        _updateChangeOutput();
        return this;
    }

    Transaction withFeePerKb(int newFee) {
        this._feePerKb = newFee;
        _updateChangeOutput();
        return this;
    }

    /// Sort inputs and outputs according to Bip69
    ///
    Transaction sort() {
        _sortInputs(this._txnInputs);
        _sortOutputs(this._txnOutputs);
        return this;
    }

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified date
    ///
    /// [future] - The date in future before which transaction will not be spendable.
    Transaction lockUntilDate(DateTime future) {
        if (future.millisecondsSinceEpoch < NLOCKTIME_BLOCKHEIGHT_LIMIT)
            throw new LockTimeException("Block time is set too early");

        for (var input in this._txnInputs) {
            if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
                input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
            }
        }

        this._nLockTime = future.millisecondsSinceEpoch;

        return this;
    }

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified date
    ///
    /// [timestamp] - The date in future before which transaction will not be spendable.
    Transaction lockUntilUnixTime(int timestamp) {
        if (timestamp < NLOCKTIME_BLOCKHEIGHT_LIMIT)
            throw new LockTimeException("Block time is set too early");

        this._nLockTime = timestamp;

        return this;
    }

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified block height
    ///
    /// [blockheight] - The block height before which transaction will not be spendable.
    Transaction lockUntilBlockHeight(int blockHeight) {
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
        this._nLockTime = blockHeight;

        return this;
    }

    ///Returns either DateTime or int (blockHeight)
    ///Yes, the return type overloading sucks. Welcome to bitcoin.
    getLockTime() {
        //FIXME: Figure out how to use Type System to force consumer of this
        // method to think about the return value. e.g. scala.Option

        var timestamp = this._nLockTime;
        if (timestamp < 500000000) {
            return timestamp;
        } else {
            var date = DateTime.fromMillisecondsSinceEpoch(timestamp);
            return date;
        }
    }

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
        if (this
            .serialize(performChecks: false)
            .length > MAX_BLOCK_SIZE) {
            return 'transaction over the maximum block size';
        }

        // Check for duplicate inputs
        var txinmap = {};
        for (var i = 0; i < this.inputs.length; i++) {
            var txin = this.inputs[i];

            var inputid = txin.prevTxnId + ":" + txin.outputIndex.toString();
            if (txinmap[inputid] != null) {
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


    bool verifySignature(SVSignature sig, SVPublicKey pubKey, int inputNumber, SVScript subscript, BigInt satoshis, int flags){
        String hash = Sighash().hash(this, sig.nhashtype, inputNumber, subscript, satoshis, flags: flags);

        var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());

        ECPublicKey publicKey = new ECPublicKey(pubKey.point, _domainParams);

        _dsaSigner.init(false, PublicKeyParameter(publicKey));

        Uint8List decodedMessage = Uint8List.fromList(HEX.decode(reversedHash).toList());
        return _dsaSigner.verifySignature(decodedMessage,ECSignature(sig.r, sig.s));
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
    ///
    ///  *NOTE* : This fee calculation strategy is taken from the MoneyButton/BSV library.
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


    bool _invalidSatoshis() {
        return this._txnOutputs.fold(true, (bool valid, TransactionOutput output) => valid && output.invalidSatoshis());
    }


    _doSerializationChecks() {
        if (this._invalidSatoshis()) {
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

        if (!this._isFullySigned())
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

    void _parseTransactionHex(String txnHex) {
        var buffer = HEX.decode(txnHex);

        ByteDataReader reader = ByteDataReader();
        reader.add(buffer);

        _fromBufferReader(reader);
    }

    void _fromBufferReader(ByteDataReader reader) {
        var i, sizeTxIns, sizeTxOuts;

        this._version = reader.readInt32(Endian.little);
        sizeTxIns = readVarIntNum(reader);
        for (i = 0; i < sizeTxIns; i++) {
            var input = TransactionInput.fromReader(reader);
            this._txnInputs.add(input);
        }

        sizeTxOuts = readVarIntNum(reader);
        for (i = 0; i < sizeTxOuts; i++) {
            var output = TransactionOutput.fromReader(reader);
            this._txnOutputs.add(output);
        }

        this._nLockTime = reader.readUint32(Endian.little);
    }


    bool _inputExists(String transactionId, int outputIndex) =>
        this._txnInputs
            .where((input) => input.prevTxnId == transactionId && input.outputIndex == outputIndex)
            .isNotEmpty;

    void _removeChangeOutputs() {
        _txnOutputs.removeWhere((elem) => elem.isChangeOutput);
    }

    bool _isFullySigned() {
        return this._txnInputs.fold(true, (prev, elem) => prev && elem.isFullySigned());
    }

    void _updateChangeOutput() {
        if (this._changeAddress == null) return;

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



    BigInt _nonChangeRecipientTotals() {
        return this._txnOutputs
            .where((txnOut) => !txnOut.isChangeOutput)
            .fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);
    }

    BigInt _recipientTotals() => this._txnOutputs.fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);

    BigInt _inputTotals() => this._txnInputs.fold(BigInt.zero, (BigInt prev, elem) => prev + elem.satoshis);

    BigInt _recalculateChange() {
        var inputAmount = _inputTotals();
        var outputAmount = _nonChangeRecipientTotals();
        var unspent = inputAmount - outputAmount;

        return unspent - getFee();
    }

    bool _hasChangeScript() => this._changeScriptFlag; //{
//        return this._txnOutputs.fold(false, (prev, elem) => prev || elem.isChangeOutput);
    //}


    /// Estimates fee from serialized transaction size in bytes.
    BigInt _getUnspentValue() {
        BigInt inputAmount = _inputTotals();
        BigInt outputAmount = this._txnOutputs.fold(BigInt.zero, (BigInt prev, TransactionOutput elem) => prev + elem.satoshis);

        return inputAmount - outputAmount;
    }

    BigInt _estimateFee() {

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
        });

        this._txnOutputs.forEach((output) {
            result += HEX
                .decode(output.script.toHex())
                .length + 9; // <---- HOW DO WE CALCULATE SCRIPT FROM JUST AN ADDRESS !? AND LENGTH ???
        });

        return result;
    }

    void _sortInputs(List<TransactionInput> txns) {
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

    void _sortOutputs(List<TransactionOutput> txns) {
        txns.sort((lhs, rhs) {
            var satoshiComparison = lhs.satoshis - rhs.satoshis;
            if (satoshiComparison != BigInt.zero)
                return satoshiComparison > BigInt.zero ? 1 : -1;
            else
                return lhs.scriptHex.compareTo(rhs.scriptHex);
        });
    }

    /// Returns the total amount of satoshis in all outputs
    BigInt get outputAmount => this._recipientTotals();

    /// Returns the total amount of satoshis in all inputs
    BigInt get inputAmount => this._inputTotals();

    /// Returns the transaction version number
    int get version {
        return this._version;
    }

    /// Sets the transaction version number
    ///
    /// [version] - the version number
    void set version(int version) {
        this._version = version;
    }

    /// Gets the time until this transaction may be included in a block.
    ///
    /// *NOTE* : Transaction locktime is either a date (denoted as a unix timestamp),
    /// or a blockheight.
    ///
    /// If nLocktime < 500000000 , then it's a blockheight. Anytime over that number
    /// is interpreted as a timestamp.
    /// If all inputs in a transaction have [TransactionInput.sequenceNumber] equal to UINT_MAX, then nLockTime is ignored.
    int get nLockTime {
        return this._nLockTime;
    }

    /// Sets the time before this transaction may be included in a block.
    void set nLockTime(int lockTime) {
        this._nLockTime = lockTime;
    }

    /// Returns a list of all the [TransactionInput]s
    List<TransactionInput> get inputs {
        return this._txnInputs;
    }

    /// Returns a list of all the [TransactionOutput]s
    List<TransactionOutput> get outputs {
        return this._txnOutputs;
    }

    /// Returns the current set of options that govern which checks are performed
    /// when serializing to raw hex format.
    Set<TransactionOption> get transactionOptions => _transactionOptions;


}
