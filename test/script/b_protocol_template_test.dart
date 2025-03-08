import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/script/templates/b_protocol_template.dart';
import 'package:test/test.dart';

void main() {
  group('BProtocol Template', () {
    late BProtocolTemplate template;
    late SVScript bProtocolScript;
    late String testData;
    late String mediaType;
    late String encoding;
    late String? filename;

    setUp(() {
      template = BProtocolTemplate();
      testData = 'Hello, Bitcoin SV!';
      mediaType = 'text/plain';
      encoding = 'utf-8';
      filename = 'message.txt';
      
      // Create a B-Protocol script
      final builder = BProtocolLockingScriptBuilder(
        utf8.encode(testData),
        mediaType,
        encoding,
        filename: filename
      );
      bProtocolScript = builder.getScriptPubkey();
    });

    test('should have correct name', () {
      expect(template.name, equals('BProtocol'));
    });

    test('should match BProtocol script', () {
      expect(template.matches(bProtocolScript), isTrue);
      
      // Should not match other script types
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(template.matches(p2pkScript), isFalse);
    });

    test('should create builder with string data', () {
      final params = {
        'data': testData,
        'mediaType': mediaType,
        'encoding': encoding,
        'filename': filename
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<BProtocolLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(bProtocolScript.toString()));
    });

    test('should create builder with Uint8List data', () {
      final dataBytes = Uint8List.fromList(utf8.encode(testData));
      final params = {
        'data': dataBytes,
        'mediaType': mediaType,
        'encoding': encoding,
        'filename': filename
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<BProtocolLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(bProtocolScript.toString()));
    });

    test('should create builder with List<int> data', () {
      final dataList = utf8.encode(testData);
      final params = {
        'data': dataList,
        'mediaType': mediaType,
        'encoding': encoding,
        'filename': filename
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<BProtocolLockingScriptBuilder>());
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(bProtocolScript.toString()));
    });

    test('should create builder without filename', () {
      final params = {
        'data': testData,
        'mediaType': mediaType,
        'encoding': encoding
      };
      final builder = template.createBuilder(params);
      
      expect(builder, isA<BProtocolLockingScriptBuilder>());
      
      // Create a script without filename for comparison
      final builderWithoutFilename = BProtocolLockingScriptBuilder(
        utf8.encode(testData),
        mediaType,
        encoding
      );
      final scriptWithoutFilename = builderWithoutFilename.getScriptPubkey();
      
      final script = builder.getScriptPubkey();
      expect(script.toString(), equals(scriptWithoutFilename.toString()));
    });

    test('should throw error when required parameters are missing', () {
      // Missing data
      final params1 = {
        'mediaType': mediaType,
        'encoding': encoding
      };
      expect(() => template.createBuilder(params1), throwsArgumentError);
      
      // Missing mediaType
      final params2 = {
        'data': testData,
        'encoding': encoding
      };
      expect(() => template.createBuilder(params2), throwsArgumentError);
      
      // Missing encoding
      final params3 = {
        'data': testData,
        'mediaType': mediaType
      };
      expect(() => template.createBuilder(params3), throwsArgumentError);
    });

    test('should throw error when data is invalid type', () {
      final params = {
        'data': 12345, // Integer is not a valid type
        'mediaType': mediaType,
        'encoding': encoding
      };
      expect(() => template.createBuilder(params), throwsArgumentError);
    });

    test('should throw error when creating unlocking builder', () {
      final params = <String, dynamic>{};
      expect(() => template.createUnlockingBuilder(params), throwsUnsupportedError);
    });

    test('should always return false for canBeSatisfiedBy', () {
      final publicKey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      final availableKeys = [publicKey];
      
      expect(template.canBeSatisfiedBy(availableKeys, bProtocolScript), isFalse);
    });

    test('should extract script info', () {
      final info = template.extractScriptInfo(bProtocolScript);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('BProtocol'));
      expect(info['prefix'], equals('19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut'));
      expect(info['data'], isA<Uint8List>());
      expect(info['mediaType'], equals(mediaType));
      expect(info['encoding'], equals(encoding));
      expect(info['filename'], equals(filename));
      
      // Convert the data back to a string and verify it matches
      final extractedData = utf8.decode(info['data']);
      expect(extractedData, equals(testData));
    });

    test('should extract script info without filename', () {
      // Create a script without filename
      final builderWithoutFilename = BProtocolLockingScriptBuilder(
        utf8.encode(testData),
        mediaType,
        encoding
      );
      final scriptWithoutFilename = builderWithoutFilename.getScriptPubkey();
      
      final info = template.extractScriptInfo(scriptWithoutFilename);
      
      expect(info, isA<Map<String, dynamic>>());
      expect(info['type'], equals('BProtocol'));
      expect(info['prefix'], equals('19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut'));
      expect(info['data'], isA<Uint8List>());
      expect(info['mediaType'], equals(mediaType));
      expect(info['encoding'], equals(encoding));
      expect(info['filename'], isNull);
    });

    test('should throw error when extracting info from non-BProtocol script', () {
      final p2pkScript = SVScript.fromString('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG');
      expect(() => template.extractScriptInfo(p2pkScript), throwsArgumentError);
    });
  });
}
