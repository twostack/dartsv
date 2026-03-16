import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';

/// Contract for signing transaction inputs.
///
/// The only method consumers call is [sign]. Implementations decide
/// where the private key lives — in memory, in a hardware device, or
/// behind a callback into a secure context.
abstract class TransactionSigner {
  int get sigHashType;

  /// Sign a single input of [unsignedTxn] that spends [utxo] at [inputIndex].
  ///
  /// The implementation computes the sighash, produces an [SVSignature],
  /// and attaches it to the input's [UnlockingScriptBuilder].
  Transaction sign(Transaction unsignedTxn, TransactionOutput utxo, int inputIndex);

  /// Sign a raw sighash preimage. Utility used by some unlock builders.
  SVSignature signPreimage(Uint8List preImage);
}

/// Default implementation that holds the private key in memory.
class DefaultTransactionSigner extends TransactionSigner {
  @override
  final int sigHashType;
  final SVPrivateKey signingKey;

  DefaultTransactionSigner(this.sigHashType, this.signingKey);

  @override
  Transaction sign(Transaction unsignedTxn, TransactionOutput utxo, int inputIndex) {
    SVScript subscript = utxo.script;
    var sigHash = Sighash();

    var hash = sigHash.hash(unsignedTxn, sigHashType, inputIndex, subscript, utxo.satoshis);
    var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());
    var preImage = sigHash.preImage;

    if (preImage == null) throw SignatureException("Preimage calculation failed");

    var sig = SVSignature.fromPrivateKey(signingKey);
    sig.nhashtype = sigHashType;
    sig.sign(reversedHash);

    TransactionInput input = unsignedTxn.inputs[inputIndex];
    if (input != null) {
      UnlockingScriptBuilder scriptBuilder = input.scriptBuilder!;
      scriptBuilder.signatures.add(sig);
    } else {
      throw TransactionException(
          "Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
    }

    return unsignedTxn;
  }

  @override
  SVSignature signPreimage(Uint8List preImage) {
    var hash = sha256Twice(preImage.toList());
    var hashHex = HEX.encode(hash);

    var sig = SVSignature.fromPrivateKey(signingKey);
    sig.nhashtype = sigHashType;
    sig.sign(hashHex);

    return sig;
  }

  /// Static utility for signing a preimage with an explicit key and sighash type.
  static SVSignature signPreimageWithKey(SVPrivateKey key, Uint8List preImage, int sigHashType) {
    var hash = sha256Twice(preImage.toList());
    var hashHex = HEX.encode(hash);

    var sig = SVSignature.fromPrivateKey(key);
    sig.nhashtype = sigHashType;
    sig.sign(hashHex);

    return sig;
  }
}
