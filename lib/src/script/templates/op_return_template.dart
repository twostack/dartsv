import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';

/// Implementation of the OP_RETURN script template for storing data on the blockchain
class OpReturnTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "OP_RETURN";
  
  @override
  String get name => TEMPLATE_NAME;
  
  @override
  bool matches(SVScript script) {
    return ScriptPattern.isOpReturn(script);
  }
  
  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('data')) {
      throw ArgumentError('OP_RETURN template requires data parameter');
    }
    
    final data = params['data'];
    Uint8List dataBytes;
    
    if (data is String) {
      dataBytes = Uint8List.fromList(data.codeUnits);
    } else if (data is Uint8List) {
      dataBytes = data;
    } else if (data is List<int>) {
      dataBytes = Uint8List.fromList(data);
    } else {
      throw ArgumentError('Data must be a String, Uint8List, or List<int>');
    }
    
    return OpReturnLockingScriptBuilder(dataBytes);
  }
  
  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    // OP_RETURN scripts cannot be spent, so there's no unlocking script
    throw UnsupportedError('OP_RETURN scripts cannot be spent');
  }
  
  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // OP_RETURN scripts cannot be spent
    return false;
  }
  
  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match OP_RETURN template');
    }
    
    final chunks = script.chunks;
    
    // If there's only one chunk (OP_RETURN), there's no data
    if (chunks.length == 1) {
      return {
        'type': TEMPLATE_NAME,
        'data': Uint8List(0),
      };
    }
    
    // Extract the data from the second chunk
    final data = chunks[1].buf ?? Uint8List(0);
    
    return {
      'type': TEMPLATE_NAME,
      'data': data,
    };
  }
}

/// OP_RETURN Locking Script Builder
class OpReturnLockingScriptBuilder extends LockingScriptBuilder {
  Uint8List _data;
  
  OpReturnLockingScriptBuilder(this._data) {
    // Check data size (Bitcoin SV allows larger OP_RETURN data than Bitcoin Core)
    if (_data.length > 100000) {
      throw ArgumentError('OP_RETURN data is too large (max 100KB)');
    }
  }
  
  @override
  SVScript getScriptPubkey() {
    final scriptBuilder = ScriptBuilder()
      ..opCode(OpCodes.OP_RETURN);
    
    if (_data.isNotEmpty) {
      scriptBuilder.addData(_data);
    }
    
    return scriptBuilder.build();
  }
  
  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isOpReturn(script)) {
      throw ArgumentError('Script is not a valid OP_RETURN script');
    }
    
    final chunks = script.chunks;
    
    // If there's only one chunk (OP_RETURN), there's no data
    if (chunks.length == 1) {
      _data = Uint8List(0);
      return;
    }
    
    // Extract the data from the second chunk
    final buf = chunks[1].buf;
    _data = buf != null ? Uint8List.fromList(buf) : Uint8List(0);
  }
}
