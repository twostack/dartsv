import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/transaction/default_builder.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';

class TransactionSigner {
  int sigHashType;
  SVPrivateKey signingKey;

  TransactionSigner(this.sigHashType, this.signingKey);

  /** Signs the provided transaction, and populates the corresponding input's
   *  LockingScriptBuilder with the signature. Responsibility for what to
   *  do with the Signature (populate appropriate template) is left to the
   *  LockingScriptBuilder instance
   *
   *
   * @param unsignedTxn  - Unsigned Transaction
   * @param utxo - Funding transaction's Output to sign over
   * @param inputIndex - Input of the current Transaction we are signing for
   * @param signingKey - Private key to sign with
   * @param sigHashType - Flags that govern which SigHash algorithm is applied
   * @return Signed Transaction
   * @throws TransactionException
   * @throws IOException
   * @throws SigHashException
   * @throws SignatureDecodeException
   */
  Transaction sign(Transaction unsignedTxn,
      TransactionOutput utxo,
      int inputIndex) {

    //FIXME: This is a test work-around for why I can't sign an unsigned raw txn
    //FIXME: This should account for ANYONECANPAY mask that limits outputs to sign over
    //      NOTE: Stripping Subscript should be done inside SIGHASH class
    SVScript subscript = utxo.script;
    var sigHash = Sighash();

    //NOTE: Return hash in LittleEndian (already double-sha256 applied)
    var pi = sigHash.createSighashPreImage(unsignedTxn, sigHashType, inputIndex, subscript, utxo.satoshis);
    var hash = sigHash.hash(unsignedTxn, sigHashType, inputIndex, subscript, utxo.satoshis);
    var reversedHash = HEX.encode(HEX.decode(hash).reversed.toList());
    var preImage = sigHash.preImage;
    var preImageHex = HEX.encode(preImage!.toList());

    if (preImage == null) throw SignatureException(
        "Preimage calcumation failed");

    // SVSignature sig = signPreimage(signingKey, preImage, sigHashType);

    var sig = SVSignature.fromPrivateKey(signingKey);
    sig.nhashtype = sigHashType;
    sig.sign(reversedHash);

    TransactionInput input = unsignedTxn.inputs[inputIndex];
    if (input != null){
      UnlockingScriptBuilder scriptBuilder = input.scriptBuilder!; //force failure on null script
      scriptBuilder.signatures.add(sig);
    } else {
      throw new TransactionException(
          "Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
    }

    return unsignedTxn; //signature has been added
  }

  static SVSignature signPreimage(SVPrivateKey signingKey, Uint8List preImage, int sigHashType) {

    var hash = sha256Twice(preImage.toList());
    var hashHex = HEX.encode(hash);

    //FIXME: This kind of required round-tripping into the base class of TransactionSignature smells funny
    //       We should have a cleaner constructor for TransactionSignature
    var sig = SVSignature.fromPrivateKey(signingKey);
    sig.nhashtype = sigHashType;
    sig.sign(hashHex);

    return sig;
  }

}
