import 'dart:collection';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/transaction_input.dart';
import 'package:dartsv/src/transaction/transaction_output.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'dart:typed_data';
import 'package:buffer/buffer.dart';

import 'locking_script_builder.dart';

/// When serializing the transaction to hexadecimal it is possible
/// to selectively disable some checks. See [Transaction.serialize()]
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
/// and one or more [TransactionOutput]s which represent either the sending of coins
/// to a recipient or the creation of 'data'-only output.
///
///
/// The raw hex transaction has the following layout:
///
/// `4 bytes`  - Transaction version number; currently version 1 or 2.
/// Programs creating transactions using er consensus rules may use higher version numbers.
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
  int _version = 2;
  int _nLockTime = 0;
  final List<TransactionInput> _txnInputs = []; //this transaction's inputs
  final List<TransactionOutput> _txnOutputs = []; //this transaction's outputs
  final List<TransactionOutput> _utxos = []; //the UTXOs from spent Transaction
  Address? _changeAddress;
  LockingScriptBuilder? _changeScriptBuilder;
  final Set<TransactionOption> _transactionOptions = Set<TransactionOption>();

  List<int>? _txHash;
  String? _txId;

  static final SHA256Digest _sha256Digest = SHA256Digest();
  final ECDSASigner _dsaSigner = ECDSASigner(null, HMac(_sha256Digest, 64));
  final ECDomainParameters _domainParams = ECDomainParameters('secp256k1');

  BigInt? _fee;
  bool _changeScriptFlag = false;

  var CURRENT_VERSION = 1;
  var DEFAULT_NLOCKTIME = 0;
  var MAX_BLOCK_SIZE = 1000000;

  /// Minimum amount for an output for it not to be considered a dust output
  static final DUST_AMOUNT = BigInt.from(546);

  /// Margin of error to allow fees in the vecinity of the expected value but doesn't allow a big difference
  static final FEE_SECURITY_MARGIN = BigInt.from(150);

  /// max amount of satoshis in circulation
  static final MAX_MONEY = BigInt.from(21000000 * 1e8);



  /// Max value for an unsigned 32 bit value
  static final NLOCKTIME_MAX_VALUE = 4294967295;

  /// Safe upper bound for change address script size in bytes
  static final CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
  static final MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;
  static final SCRIPT_MAX_SIZE = 149;


  //Default, zero-argument constructor
  Transaction();

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
  //Transaction();

  /// Creates a  Transaction instance from a JSON or MAP object.
  /// The Transaction is implicitly treated as a P2PKH Transaction
  ///
  /// ### Expected JSON/Map Format
  /// ```
  ///    {
  ///      'hash':'a6f7b4284fb753eab9b554283c4fe1f1d7e143e6cf3b975d0376d7c08ba4cdf5',
  ///      'version':1,
  ///      'inputs':[
  ///        {
  ///          'prevTxId':'0000000000000000000000000000000000000000000000000000000000000000',
  ///          'outputIndex':4294967295,
  ///          'sequenceNumber':4294967295,
  ///          'script':'03e45201062f503253482f'
  ///        }
  ///      ],
  ///      'outputs':[
  ///        {
  ///          'satoshis':5001000000,
  ///          'script':'76a914ee9a7590f91e04832054f0645bbf243c9fac8e2288ac'
  ///        },
  ///        {
  ///          'satoshis':0,
  ///          'script':'4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac'
  ///        },
  ///        {
  ///          'satoshis':0,
  ///          'script':'2458e99e66e2b90bd8b2a0e2bfcce91e1f09ee7621d95e9a728ca2372d45df3ded00000000'
  ///        }
  ///      ],
  ///      'nLockTime':0
  ///    },
  /// ```
  Transaction.fromJSONMap(LinkedHashMap<String, dynamic> map) {
    _version = map['version'];
    _nLockTime = map['nLockTime'];
    (map['inputs'] as List).forEach((input) {
      var tmpTx = TransactionInput(input['prevTxId'], input['outputIndex'], input['sequenceNumber'], scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript.fromHex(input['script'])));
      _txnInputs.add(tmpTx);
    });

    (map['outputs'] as List).forEach((output) {
      var txOut = TransactionOutput(BigInt.from(output['satoshis']), SVScript.fromHex(output['script']));
      _txnOutputs.add(txOut);
    });
  }

  /// Constructs a  transaction instance from the raw hexadecimal string.
  Transaction.fromHex(String txnHex) {
    List<int> hash = sha256Twice(HEX.decode(txnHex)).reversed.toList();
    _txHash = hash;
    _txId = HEX.encode(_txHash!);
    _parseTransactionHex(txnHex);
  }

  /// Constructs a  transaction from a ByteDataReader which has been
  /// initialized with the raw hex data containing a complete transaction.
  Transaction.fromBufferReader(ByteDataReader reader) {
    _fromBufferReader(reader);
  }

  /// Renders this transaction as a Map/Object. See [fromJSONMap()] for example format.
  Map<String, dynamic> toObject() {
    return {
      'hash': id,
      'version': _version,
      'inputs': _txnInputs.map((input) => input.toObject()).toList(),
      'outputs': _txnOutputs.map((output) => output.toObject()).toList(),
      'nLockTime': _nLockTime
    };
  }

  //The hash is the double-sha256 of the serialized transaction (reversed)
  List<int> _getHash() {
    List<int> hash = sha256Twice(HEX.decode(serialize()));
    return hash;
  }

  //The id is the hex encoded form of the hash
  String _getId() {
    var id = HEX.encode(_getHash().reversed.toList());
    _txId = id;
    return _txId!;
  }

  /// Returns the transaction ID.
  ///
  /// The transaction ID is the double-sha256 of the raw (hexadecimal) transaction.
  String get id => _getId();

  // transaction Hash - FIXME: I thought 'id' should be equal to 'hash' ? VALIDATE !
  /// Returns the double-sha256 of the raw (hexadecimal) transaction
  List<int> get hash => _getHash();

  /// Serialize the transaction object to it's raw hexadecimal representation, ready to be
  /// broadcast to the network, or to be passed to a peer.
  /// Returns the raw transaction as a hexadecimal string.

  /// Returns the raw transaction as a hexadecimal string, skipping all checks.
  String serialize() {
    ByteDataWriter writer = ByteDataWriter();

    // set the transaction version
    writer.writeInt32(version, Endian.little);

    // set the number of inputs
    writer.write(varintBufNum(inputs.length));

    // write the inputs
    inputs.forEach((input) {
      writer.write(input.serialize());
    });

    //set the number of outputs to come
    writer.write(varintBufNum(outputs.length));

    // write the outputs
    outputs.forEach((output) {
      writer.write(output.serialize());
    });

    // write the locktime
    writer.writeUint32(nLockTime, Endian.little);

    return HEX.encode(writer.toBytes().toList());
  }

  Transaction addOutput(TransactionOutput txOutput) {
    outputs.add(txOutput);
    return this;
  }

  Transaction addInput(TransactionInput input) {
    _txnInputs.add(input);
    return this;
  }

  /// Sort inputs and outputs according to Bip69
  ///
  Transaction sort() {
    _sortInputs(_txnInputs);
    _sortOutputs(_txnOutputs);
    return this;
  }


  ///Returns either DateTime or int (blockHeight)
  ///Yes, the return type overloading sucks. Welcome to bitcoin.
  getLockTime() {
    //FIXME: Figure out how to use Type System to force consumer of this
    // method to think about the return value. e.g. scala.Option

    var timestamp = _nLockTime;
    if (timestamp < 500000000) {
      return timestamp;
    } else {
      var date = DateTime.fromMillisecondsSinceEpoch(timestamp);
      return date;
    }
  }

  String verify() {
    // Basic checks that don't depend on any context
    if (_txnInputs.isEmpty) {
      return 'transaction txins empty';
    }

    if (_txnOutputs.isEmpty) {
      return 'transaction txouts empty';
    }

    // Check for negative or overflow output values
    var valueoutbn = BigInt.zero;
    var ndx = 0;
    for (var txout in _txnOutputs) {
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
    if (serialize().length > MAX_BLOCK_SIZE) {
      return 'transaction over the maximum block size';
    }

    // Check for duplicate inputs
    var txinmap = {};
    for (var i = 0; i < inputs.length; i++) {
      var txin = inputs[i];

      var inputid = txin.prevTxnId + ':' + txin.prevTxnOutputIndex.toString();
      if (txinmap[inputid] != null) {
        return 'transaction input ' + i.toString() + ' duplicate input';
      }
      txinmap[inputid] = true;
    }

    if (isCoinbase()) {
      var script = inputs[0].script ??= SVScript();
      var buf = script.buffer;
      if (buf.length < 2 || buf.length > 100) {
        return 'coinbase transaction script size invalid';
      }
    } else {
      for (var i = 0; i < inputs.length; i++) {
        if (inputs[i] == null) {
          return 'transaction input ' + i.toString() + ' has null input';
        }
      }
    }
    return ''; //FIXME: Return a boolean value like a real programmer FFS !
  }

  bool isCoinbase() {
    //if we have a Transaction with one input, and a prevTransactionId of zeroooos, it's a coinbase.
    return (_txnInputs.length == 1 &&
        (_txnInputs[0].prevTxnId == null ||
            _txnInputs[0].prevTxnId.replaceAll('0', '').trim() == ''));
  }

  bool _invalidSatoshis() {
    return _txnOutputs.fold(
        true,
        (bool valid, TransactionOutput output) =>
            valid && output.invalidSatoshis());
  }

  void _parseTransactionHex(String txnHex) {
    var buffer = HEX.decode(txnHex);

    ByteDataReader reader = ByteDataReader();
    reader.add(buffer);

    _fromBufferReader(reader);
  }

  void _fromBufferReader(ByteDataReader reader) {
    var i, sizeTxIns, sizeTxOuts;

    _version = reader.readInt32(Endian.little);
    sizeTxIns = readVarIntNum(reader);
    for (i = 0; i < sizeTxIns; i++) {
      var input = TransactionInput.fromReader(reader);
      _txnInputs.add(input);
    }

    sizeTxOuts = readVarIntNum(reader);
    for (i = 0; i < sizeTxOuts; i++) {
      var output = TransactionOutput.fromReader(reader);
      _txnOutputs.add(output);
    }

    _nLockTime = reader.readUint32(Endian.little);
  }

  bool _inputExists(String transactionId, int outputIndex) => _txnInputs
      .where((input) =>
          input.prevTxnId == transactionId &&
          input.prevTxnOutputIndex == outputIndex)
      .isNotEmpty;

  bool _hasChangeScript() => _changeScriptFlag;

  void _sortInputs(List<TransactionInput> txns) {
    txns.sort((lhs, rhs) {
      var txnIdComparison = lhs.prevTxnId.compareTo(rhs.prevTxnId);

      if (txnIdComparison != 0) {
        //we use the prevTxnId to sort
        return txnIdComparison;
      } else {
        //txnIds can't be used (probably 'cause there's only one)
        return lhs.prevTxnOutputIndex - rhs.prevTxnOutputIndex;
      }
    });
  }

  void _sortOutputs(List<TransactionOutput> txns) {
    txns.sort((lhs, rhs) {
      var satoshiComparison = lhs.satoshis - rhs.satoshis;
      if (satoshiComparison != BigInt.zero) {
        return satoshiComparison > BigInt.zero ? 1 : -1;
      } else {
        return lhs.scriptHex.compareTo(rhs.scriptHex);
      }
    });
  }

  //FIXME: Check under which circumstances this long list of params is actually required. Can be trimmed ?
  bool verifySignature(SVSignature sig, SVPublicKey pubKey, int inputNumber, SVScript subscript, BigInt? satoshis, int flags){
    var sigHash = Sighash();
    var hash = sigHash.hash(this, sig.nhashtype, inputNumber, subscript, satoshis, flags: flags);

    var publicKey =  ECPublicKey(pubKey.point, _domainParams);

    _dsaSigner.init(false, PublicKeyParameter(publicKey));

    var decodedMessage = Uint8List.fromList(HEX.decode(hash).reversed.toList()); //FIXME: More reversi !
    return _dsaSigner.verifySignature(decodedMessage,ECSignature(sig.r, sig.s));
  }

  /// Returns the transaction version number
  int get version {
    return _version;
  }

  /// Sets the transaction version number
  ///
  /// [version] - the version number
  set version(int version) {
    _version = version;
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
    return _nLockTime;
  }

  /// Sets the time before this transaction may be included in a block.
  set nLockTime(int lockTime) {
    _nLockTime = lockTime;
  }

  /// Returns a list of all the [TransactionInput]s
  List<TransactionInput> get inputs {
    return _txnInputs;
  }

  /// Returns a list of all the [TransactionOutput]s
  List<TransactionOutput> get outputs {
    return _txnOutputs;
  }

  /// Returns the current set of options that govern which checks are performed
  /// when serializing to raw hex format.
  Set<TransactionOption> get transactionOptions => Set.unmodifiable(_transactionOptions);

  void addInputs(inputs) {
    this.inputs.addAll(inputs);
  }

  void addOutputs(outputs) {
    this.outputs.addAll(outputs);
  }
}

//mixin SignatureMixin on _SignedTransaction{
//
//
//}
//
//abstract class _SignedTransaction extends Transaction{
//    SVSignature signature;
//    _SignedTransaction(this.signature);
//
//}
//
//class SignedTransaction extends _SignedTransaction with SignatureMixin {
//    SignedTransaction(SVSignature signature) : super(signature);
//}
