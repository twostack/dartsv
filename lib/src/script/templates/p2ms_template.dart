import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:hex/hex.dart';

/// Implementation of the P2MS (Pay to MultiSig) script template
class P2MSTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "P2MS";

  @override
  String get name => TEMPLATE_NAME;

  @override
  bool matches(SVScript script) {
    return ScriptPattern.isP2MS(script);
  }

  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('publicKeys') || !params.containsKey('threshold')) {
      throw ArgumentError(
          'P2MS template requires publicKeys and threshold parameters');
    }

    final publicKeys = params['publicKeys'] as List<SVPublicKey>;
    final threshold = params['threshold'] as int;

    return P2MSLockingScriptBuilder(publicKeys, threshold);
  }

  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('signatures')) {
      throw ArgumentError('P2MS template requires signatures parameter');
    }

    final signatures = params['signatures'] as List<SVSignature>;
    final builder = P2MSUnlockingScriptBuilder();

    for (var signature in signatures) {
      builder.addSignature(signature);
    }

    return builder;
  }

  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    if (!matches(script)) return false;

    final info = extractScriptInfo(script);
    final requiredKeys = info['publicKeys'] as List<SVPublicKey>;
    final threshold = info['threshold'] as int;

    // Count how many of the required keys we have available
    int matchCount = 0;
    for (var requiredKey in requiredKeys) {
      for (var availableKey in availableKeys) {
        // Compare public keys by their hex representation instead of using point.equals
        if (requiredKey.toString() == availableKey.toString()) {
          matchCount++;
          break;
        }
      }
    }

    // We can satisfy the script if we have at least the threshold number of keys
    return matchCount >= threshold;
  }

  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match P2MS template');
    }

    final chunks = script.chunks;
    final n = SVScript.decodeFromOpN(chunks[chunks.length - 2].opcodenum);
    final m = SVScript.decodeFromOpN(chunks[0].opcodenum);

    final publicKeys = <SVPublicKey>[];
    for (int i = 1; i < chunks.length - 2; i++) {
      publicKeys.add(SVPublicKey.fromHex(HEX.encode(chunks[i].buf!)));
    }

    return {
      'type': TEMPLATE_NAME,
      'threshold': m,
      'signaturesRequired': m,
      'totalKeys': n,
      'publicKeys': publicKeys,
    };
  }
}

/// P2MS Locking Script Builder
class P2MSLockingScriptBuilder extends LockingScriptBuilder {
  List<SVPublicKey> _publicKeys;
  int _threshold;

  P2MSLockingScriptBuilder(this._publicKeys, this._threshold) {
    if (_threshold <= 0 || _threshold > _publicKeys.length) {
      throw ArgumentError(
          'Threshold must be between 1 and the number of public keys');
    }

    if (_publicKeys.length > 15) {
      throw ArgumentError('Maximum of 15 public keys are supported');
    }
  }

  @override
  SVScript getScriptPubkey() {
    final scriptBuilder = ScriptBuilder();

    // Add m (threshold)
    scriptBuilder.smallNum(_threshold);

    // Add public keys
    for (var key in _publicKeys) {
      scriptBuilder.addData(Uint8List.fromList(HEX.decode(key.toString())));
    }

    // Add n (total keys)
    scriptBuilder.smallNum(_publicKeys.length);

    // Add OP_CHECKMULTISIG
    scriptBuilder.opCode(OpCodes.OP_CHECKMULTISIG);

    return scriptBuilder.build();
  }

  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isP2MS(script)) {
      throw ArgumentError('Script is not a valid P2MS script');
    }

    final chunks = script.chunks;
    _threshold = SVScript.decodeFromOpN(chunks[0].opcodenum);

    _publicKeys = <SVPublicKey>[];
    for (int i = 1; i < chunks.length - 2; i++) {
      _publicKeys.add(SVPublicKey.fromHex(HEX.encode(chunks[i].buf!)));
    }
  }
}

/// P2MS Unlocking Script Builder
class P2MSUnlockingScriptBuilder extends UnlockingScriptBuilder {
  @override
  SVScript getScriptSig() {
    if (signatures.isEmpty) {
      throw StateError(
          'At least one signature is required for P2MS unlocking script');
    }

    final scriptBuilder = ScriptBuilder();

    // Add OP_0 to account for the extra value consumed by OP_CHECKMULTISIG
    scriptBuilder.opCode(OpCodes.OP_0);

    // Add signatures
    for (var signature in signatures) {
      // Convert signature to the correct format for the script
      final sigBytes = signature.toTxFormat();
      scriptBuilder.addData(Uint8List.fromList(HEX.decode(sigBytes)));
    }

    return scriptBuilder.build();
  }

  @override
  void parse(SVScript script) {
    final chunks = script.chunks;

    // Skip the first chunk (OP_0)
    for (int i = 1; i < chunks.length; i++) {
      final sigBuf = chunks[i].buf!;
      final signature = SVSignature.fromTxFormat(HEX.encode(sigBuf));
      addSignature(signature);
    }
  }
}
