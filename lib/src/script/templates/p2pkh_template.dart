import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:hex/hex.dart';

/// Implementation of the P2PKH (Pay to Public Key Hash) script template
class P2PKHTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "P2PKH";
  
  @override
  String get name => TEMPLATE_NAME;
  
  @override
  bool matches(SVScript script) {
    return ScriptPattern.isP2PKH(script);
  }
  
  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('pubKeyHash')) {
      throw ArgumentError('P2PKH template requires pubKeyHash parameter');
    }
    
    return P2PKHLockingScriptBuilder(params['pubKeyHash']);
  }
  
  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('signature') || !params.containsKey('publicKey')) {
      throw ArgumentError('P2PKH template requires signature and publicKey parameters');
    }
    
    final builder = P2PKHUnlockingScriptBuilder();
    builder.addSignature(params['signature']);
    builder.publicKey = params['publicKey'];
    return builder;
  }
  
  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    if (!matches(script)) return false;

    if (availableKeys.length <= 0) return false;
    
    // Extract the public key hash from the script
    final pubKeyHash = extractScriptInfo(script)['pubKeyHash'] as Uint8List;

    final locker = P2PKHLockBuilder.fromScript(script);

    final scriptPubkeyHash = HEX.encode(locker.pubkeyHash!);

    // Check if any of the available keys match the hash
    for (var key in availableKeys) {
      // Get the public key hash from the address
      final keyHashHex = key.toAddress(NetworkType.MAIN).pubkeyHash160;
      if (scriptPubkeyHash == keyHashHex) {
        return true;
      }
    }
    
    return false;
  }
  
  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match P2PKH template');
    }
    
    final chunks = script.chunks;
    final pubKeyHash = chunks[2].buf!;
    
    return {
      'type': TEMPLATE_NAME,
      'pubKeyHash': pubKeyHash,
    };
  }
}

/// P2PKH Locking Script Builder
class P2PKHLockingScriptBuilder extends LockingScriptBuilder {
  Uint8List _pubKeyHash;
  
  P2PKHLockingScriptBuilder(this._pubKeyHash);
  
  @override
  SVScript getScriptPubkey() {
    final scriptBuilder = ScriptBuilder()
      ..opCode(OpCodes.OP_DUP)
      ..opCode(OpCodes.OP_HASH160)
      ..addData(_pubKeyHash)
      ..opCode(OpCodes.OP_EQUALVERIFY)
      ..opCode(OpCodes.OP_CHECKSIG);
    
    return scriptBuilder.build();
  }
  
  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isP2PKH(script)) {
      throw ArgumentError('Script is not a valid P2PKH script');
    }
    
    _pubKeyHash = Uint8List.fromList(script.chunks[2].buf!);
  }
}

/// P2PKH Unlocking Script Builder
class P2PKHUnlockingScriptBuilder extends UnlockingScriptBuilder {
  SVPublicKey? _publicKey;
  
  set publicKey(SVPublicKey key) {
    _publicKey = key;
  }
  
  @override
  SVScript getScriptSig() {
    if (signatures.isEmpty || _publicKey == null) {
      throw StateError('Signature and public key are required for P2PKH unlocking script');
    }
    
    final scriptBuilder = ScriptBuilder()
      // Add the signature in the correct format
      // toTxFormat() returns a hex string, so we need to decode it first
      ..addData(Uint8List.fromList(HEX.decode(signatures[0].toTxFormat())))
      ..addData(Uint8List.fromList(HEX.decode(_publicKey!.toString())));
    
    return scriptBuilder.build();
  }
  
  @override
  void parse(SVScript script) {
    if (script.chunks.length != 2) {
      throw ArgumentError('Script is not a valid P2PKH unlocking script');
    }
    
    // Extract signature
    final sigBuf = script.chunks[0].buf!;
    // Convert the signature buffer to a hex string for the SVSignature constructor
    final sigHex = HEX.encode(sigBuf);
    final signature = SVSignature.fromTxFormat(sigHex);
    addSignature(signature);
    
    // Extract public key
    final pubKeyBuf = script.chunks[1].buf!;
    _publicKey = SVPublicKey.fromHex(HEX.encode(pubKeyBuf));
  }
}
