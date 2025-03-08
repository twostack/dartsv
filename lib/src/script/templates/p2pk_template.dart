import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_pattern.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/locking_script_builder.dart';
import 'package:dartsv/src/transaction/p2pk_builder.dart';
import 'package:dartsv/src/transaction/unlocking_script_builder.dart';

/// Implementation of the P2PK (Pay to Public Key) script template
class P2PKTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "P2PK";

  @override
  String get name => TEMPLATE_NAME;

  bool matches(SVScript script) {
    return ScriptPattern.isP2PK(script);
  }

LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('publicKey')) {
      throw ArgumentError('P2PK template requires a publicKey parameter');
    }

    final publicKey = params['publicKey'];
    SVPublicKey svPublicKey;

    if (publicKey is String) {
      // Assume it's a hex string
      svPublicKey = SVPublicKey.fromHex(publicKey);
    } else if (publicKey is SVPublicKey) {
      svPublicKey = publicKey;
    } else {
      throw ArgumentError('publicKey must be a hex String or SVPublicKey');
    }

    return P2PKLockBuilder(svPublicKey);
  }

  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('publicKey')) {
      throw ArgumentError('P2PK unlocking script requires a publicKey parameter');
    }

    final publicKey = params['publicKey'];
    SVPublicKey svPublicKey;

    if (publicKey is String) {
      // Assume it's a hex string
      svPublicKey = SVPublicKey.fromHex(publicKey);
    } else if (publicKey is SVPublicKey) {
      svPublicKey = publicKey;
    } else {
      throw ArgumentError('publicKey must be a hex String or SVPublicKey');
    }

    return P2PKUnlockBuilder(svPublicKey);
  }

  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    if (!matches(script)) {
      return false;
    }

    // Extract the public key from the script
    final chunks = script.chunks;
    final pubKeyBytes = chunks[0].buf!;
    final scriptPubKey = SVPublicKey.fromBuffer(pubKeyBytes);

    // Check if any of the available keys match the script's public key
    for (var key in availableKeys) {
      if (key.toHex() == scriptPubKey.toHex()) {
        return true;
      }
    }

    return false;
  }

  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match P2PK template');
    }

    final chunks = script.chunks;
    final pubKeyBytes = chunks[0].buf!;
    final publicKey = SVPublicKey.fromBuffer(pubKeyBytes);

    return {
      'type': TEMPLATE_NAME,
      'publicKey': publicKey,
      'publicKeyHex': publicKey.toHex(),
      'isCompressed': publicKey.isCompressed
    };
  }
}
