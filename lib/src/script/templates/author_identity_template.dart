import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:hex/hex.dart';

/// Implementation of the Author Identity Protocol script template
class AuthorIdentityTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "AuthorIdentity";
  static const String PREFIX = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
  
  @override
  String get name => TEMPLATE_NAME;
  
  @override
  bool matches(SVScript script) {
    return ScriptPattern.isAuthorIdentity(script);
  }
  
  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('signingAlgorithm') || 
        !params.containsKey('publicKey') || 
        !params.containsKey('signature')) {
      throw ArgumentError('Author Identity template requires signingAlgorithm, publicKey, and signature parameters');
    }
    
    return AuthorIdentityLockingScriptBuilder(
      params['signingAlgorithm'],
      params['publicKey'],
      params['signature']
    );
  }
  
  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    // Author Identity scripts cannot be spent, so there's no unlocking script
    throw UnsupportedError('Author Identity scripts cannot be spent');
  }
  
  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // Author Identity scripts cannot be spent
    return false;
  }
  
  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match Author Identity template');
    }
    
    final chunks = script.chunks;
    
    // Extract the signing algorithm, public key, and signature
    final signingAlgorithm = String.fromCharCodes(chunks[3].buf!);
    final publicKey = HEX.encode(chunks[4].buf!);
    final signature = base64Encode(chunks[5].buf!);
    
    return {
      'type': TEMPLATE_NAME,
      'prefix': PREFIX,
      'signingAlgorithm': signingAlgorithm,
      'publicKey': publicKey,
      'signature': signature,
    };
  }
}

/// Author Identity Locking Script Builder
class AuthorIdentityLockingScriptBuilder extends LockingScriptBuilder {
  final String _signingAlgorithm;
  final String _publicKey;
  final String _signature;
  
  AuthorIdentityLockingScriptBuilder(this._signingAlgorithm, this._publicKey, this._signature);
  
  @override
  SVScript getScriptPubkey() {
    final scriptBuilder = ScriptBuilder()
      .opFalse()
      .opCode(OpCodes.OP_RETURN)
      .addData(Uint8List.fromList(utf8.encode(AuthorIdentityTemplate.PREFIX)))
      .addData(Uint8List.fromList(utf8.encode(_signingAlgorithm)))
      .addData(Uint8List.fromList(HEX.decode(_publicKey)))
      .addData(Uint8List.fromList(base64Decode(_signature)));
    
    return scriptBuilder.build();
  }
  
  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isAuthorIdentity(script)) {
      throw ArgumentError('Script is not a valid Author Identity script');
    }
    
    // No need to extract script info or set fields since they're final,
    // but in a real implementation you might want to handle this differently
    // by using the extracted values from the script
  }
}
