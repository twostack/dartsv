import 'dart:convert';

import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/data_builder.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('building data output scripts', () {
    test('should create script from no data', () {
      var lockBuilder = DataLockBuilder(<int>[]);
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });

    test('should create script from empty data', () {
      var lockBuilder = DataLockBuilder(utf8.encode(''));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });

    test('can handle larger data pushes', (){
      var data = "3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601";

      var lockBuilder = DataLockBuilder(utf8.encode(data));
      expect(() => lockBuilder.getScriptPubkey(), returnsNormally);
    });


    test('fails if old-style OP_RETURN', () {
      var lockBuilder = DataLockBuilder([]);

      var script = SVScript.fromString('OP_RETURN');
      expect(() => lockBuilder.fromScript(script), throwsException);
    });

    test('should create script from some data', () {
      var data = HEX.decode('bacacafe0102030405');

      var lockBuilder = DataLockBuilder(data);
      var scriptPubkey = lockBuilder.getScriptPubkey();
      expect(scriptPubkey.toString(), equals('OP_0 OP_RETURN 9 0xbacacafe0102030405'));
    });

    //TODO: Add tests for other pushdata sizes

  });
}
