import 'dart:convert';

import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/data_builder.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('building data output scripts', () {
    test('should create script from no data', () {
      var lockBuilder = DataLockBuilder(null);
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });

    test('should create script from empty data', () {
      var lockBuilder = DataLockBuilder(utf8.encode(''));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });


    test('fails if old-style OP_RETURN', () {
      var lockBuilder = DataLockBuilder(null);

      var script = SVScript.fromString('OP_RETURN');
      expect(() => lockBuilder.fromScript(script), throwsException);
    });

    test('should create script from some data', () {
      var data = HEX.decode('bacacafe0102030405');
      var lockBuilder = DataLockBuilder(data);
      var scriptPubkey = lockBuilder.getScriptPubkey();
      expect(scriptPubkey.toString(), equals('OP_0 OP_RETURN 9 0xbacacafe0102030405'));
    });

  });
}
