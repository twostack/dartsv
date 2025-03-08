import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';

/// Implementation of the B-Protocol script template for storing media files on the blockchain
class BProtocolTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "BProtocol";
  static const String PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";
  
  @override
  String get name => TEMPLATE_NAME;
  
  @override
  bool matches(SVScript script) {
    return ScriptPattern.isBProtocol(script);
  }
  
  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('data') || 
        !params.containsKey('mediaType') || 
        !params.containsKey('encoding')) {
      throw ArgumentError('B-Protocol template requires data, mediaType, and encoding parameters');
    }
    
    final data = params['data'];
    final mediaType = params['mediaType'];
    final encoding = params['encoding'];
    final filename = params['filename']; // Optional
    
    List<int> dataBytes;
    
    if (data is String) {
      dataBytes = utf8.encode(data);
    } else if (data is Uint8List) {
      dataBytes = data.toList();
    } else if (data is List<int>) {
      dataBytes = data;
    } else {
      throw ArgumentError('Data must be a String, Uint8List, or List<int>');
    }
    
    return BProtocolLockingScriptBuilder(
      dataBytes,
      mediaType.toString(),
      encoding.toString(),
      filename: filename?.toString()
    );
  }
  
  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    // B-Protocol scripts cannot be spent, so there's no unlocking script
    throw UnsupportedError('B-Protocol scripts cannot be spent');
  }
  
  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // B-Protocol scripts cannot be spent
    return false;
  }
  
  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match B-Protocol template');
    }
    
    final chunks = script.chunks;
    
    // Extract the data, media type, and encoding
    final data = chunks[3].buf ?? Uint8List(0);
    final mediaType = chunks[4].buf != null ? String.fromCharCodes(chunks[4].buf!) : "";
    final encoding = chunks[5].buf != null ? String.fromCharCodes(chunks[5].buf!) : "";
    
    // Extract filename if present
    String? filename;
    if (chunks.length > 6 && chunks[6].buf != null) {
      filename = String.fromCharCodes(chunks[6].buf!);
    }
    
    return {
      'type': TEMPLATE_NAME,
      'prefix': PREFIX,
      'data': data,
      'mediaType': mediaType,
      'encoding': encoding,
      'filename': filename,
    };
  }
}

/// B-Protocol Locking Script Builder
class BProtocolLockingScriptBuilder extends LockingScriptBuilder {
  final List<int> _data;
  final String _mediaType;
  final String _encoding;
  final String? _filename;
  
  BProtocolLockingScriptBuilder(this._data, this._mediaType, this._encoding, {String? filename})
      : _filename = filename;
  
  @override
  SVScript getScriptPubkey() {
    final builder = ScriptBuilder()
        .opFalse()
        .opCode(OpCodes.OP_RETURN)
        .addData(Uint8List.fromList(utf8.encode(BProtocolTemplate.PREFIX)))
        .addData(Uint8List.fromList(_data))
        .addData(Uint8List.fromList(utf8.encode(_mediaType)))
        .addData(Uint8List.fromList(utf8.encode(_encoding)));

    if (_filename != null) {
      builder.addData(Uint8List.fromList(utf8.encode(_filename!)));
    }
    
    return builder.build();
  }
  
  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isBProtocol(script)) {
      throw ArgumentError('Script is not a valid B-Protocol script');
    }
    
    // No need to extract script info or set fields since they're final,
    // but in a real implementation you might want to handle this differently
    // by using the extracted values from the script
  }
}
