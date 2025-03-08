import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_pattern.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/locking_script_builder.dart';
import 'package:dartsv/src/transaction/p2sh_builder.dart';
import 'package:dartsv/src/transaction/unlocking_script_builder.dart';
import 'package:hex/hex.dart';

/// Implementation of the P2SH (Pay to Script Hash) script template
class P2SHTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "P2SH";

  @override
  String get name => TEMPLATE_NAME;

  bool matches(SVScript script) {
    return ScriptPattern.isP2SH(script);
  }

  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('redeemScript')) {
      throw ArgumentError('P2SH template requires a redeemScript parameter');
    }

    final redeemScript = params['redeemScript'];
    SVScript svScript;
    String scriptHash;

    if (redeemScript is String) {
      // Assume it's a hex string of the script
      svScript = SVScript.fromHex(redeemScript);
    } else if (redeemScript is SVScript) {
      svScript = redeemScript;
    } else {
      throw ArgumentError('redeemScript must be a hex String or SVScript');
    }

    // Calculate the hash160 of the redeem script
    final scriptBytes = svScript.buffer;
    final hash = hash160(scriptBytes);
    scriptHash = HEX.encode(hash);

    return P2SHLockBuilder(scriptHash);
  }

  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('redeemScript')) {
      throw ArgumentError('P2SH unlocking script requires a redeemScript parameter');
    }

    final redeemScript = params['redeemScript'];
    SVScript svScript;

    if (redeemScript is String) {
      // Assume it's a hex string of the script
      svScript = SVScript.fromHex(redeemScript);
    } else if (redeemScript is SVScript) {
      svScript = redeemScript;
    } else {
      throw ArgumentError('redeemScript must be a hex String or SVScript');
    }

    return P2SHUnlockBuilder(svScript);
  }

  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // This is complex for P2SH as it depends on the redeem script
    // For simplicity, we'll return false for now
    return false;
  }

  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match P2SH template');
    }

    final chunks = script.chunks;
    final scriptHashBytes = chunks[1].buf!;
    final scriptHash = HEX.encode(scriptHashBytes);

    return {
      'type': TEMPLATE_NAME,
      'scriptHash': scriptHash
    };
  }
}
