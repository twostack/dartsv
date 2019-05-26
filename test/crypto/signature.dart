import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:hex/hex.dart';
import 'dart:io';
import 'dart:convert';

main() {
    var derBuffer = '3044022075fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e62770220729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2';

    test('should work with conveniently setting r, s', () {
        BigInt r;
        BigInt s;
        var sig = SVSignature.fromECParams(r, s);
        expect(sig, isNotNull);
        expect(sig.r.toString(), equals(r.toString()));
        expect(sig.s.toString(), equals(s.toString()));
    });

    test('should parse this DER format signature', () {
        var sig = SVSignature.fromDER(derBuffer);
        expect(sig.r.toRadixString(16), equals('75fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e6277'));
        expect(sig.s.toRadixString(16), equals('729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2'));
    });


    test('should parse this known signature and rebuild it with updated zero-padded sighash types', () {
        var buffer = '30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e7201';
        var sig = SVSignature.fromTxFormat(buffer);
        expect(sig.nhashtype, equals(SighashType.SIGHASH_ALL));
        sig.nhashtype = SighashType.SIGHASH_ALL | SighashType.SIGHASH_ANYONECANPAY;

        expect(sig.toTxFormat(), equals(buffer.substring(0, buffer.length - 2) + '81'));
        sig.nhashtype = SighashType.SIGHASH_SINGLE;
        expect(sig.toTxFormat(), equals(buffer.substring(0, buffer.length - 2) + '03'));
    });


    test('should convert from this known tx-format buffer', () {
        var buf = '30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e7201';
        var sig = SVSignature.fromTxFormat(buf);
        expect(sig.r.toString(), equals('63173831029936981022572627018246571655303050627048489594159321588908385378810'));
        expect(sig.s.toString(), equals('4331694221846364448463828256391194279133231453999942381442030409253074198130'));
        expect(sig.nhashtype, equals(SighashType.SIGHASH_ALL));
    });

    test('should parse this known signature and rebuild it', () {
        var buf = '3044022007415aa37ce7eaa6146001ac8bdefca0ddcba0e37c5dc08c4ac99392124ebac802207d382307fd53f65778b07b9c63b6e196edeadf0be719130c5db21ff1e700d67501';
        var sig = SVSignature.fromTxFormat(buf);
        expect(sig.toTxFormat().toString(), equals(buf));
    });


    test('should parse this signature generated in node', () {
        var sig = '30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72';
        var parsed = SVSignature.fromDER(sig);

        //FIXME: Come back and check if these are needed somewhere.Seems redundant
//      parsed.header.should.equal(0x30);
//      parsed.length.should.equal(69);
//      parsed.rlength.should.equal(33);
//      parsed.rneg.should.equal(true);

//        expect(parsed.r.isNegative, isTrue);
        expect(parsed.r.toString(), equals('63173831029936981022572627018246571655303050627048489594159321588908385378810'));
        expect(parsed.rHex, equals('008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa'));
//      parsed.slength.should.equal(32)
//      parsed.sneg.should.equal(false)
        expect(parsed.s.toString(), equals('4331694221846364448463828256391194279133231453999942381442030409253074198130'));
        expect(parsed.sHex, equals('0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72'));
    });

    //Weird. Why are we checking for both the 0-padded and non-0-padded
    //versions of r & s ?
    test('should parse this DER format signature in hex', () {
        var buf = '3044022075fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e62770220729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2';
        var sig = SVSignature.fromDER(buf);
        expect(sig.r.toRadixString(16), equals('75fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e6277'));
        expect(sig.s.toRadixString(16), equals('729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2'));
    });


    test('should parse this 69 byte signature', () {
        var sighex = '3043021f59e4705959cc78acbfcf8bd0114e9cc1b389a4287fb33152b73a38c319b50302202f7428a27284c757e409bf41506183e9e49dfb54d5063796dfa0d403a4deccfa';
        var parsed = SVSignature.fromDER(sighex);
//      parsed.header.should.equal(0x30)
//      parsed.length.should.equal(67)
//      parsed.rlength.should.equal(31)
//      parsed.rneg.should.equal(false)
        expect(parsed.rHex, equals('59e4705959cc78acbfcf8bd0114e9cc1b389a4287fb33152b73a38c319b503'));
        expect(parsed.r.toString(), equals('158826015856106182499128681792325160381907915189052224498209222621383996675'));
//      parsed.slength.should.equal(32)
//      parsed.sneg.should.equal(false)
        expect(parsed.sHex, equals('2f7428a27284c757e409bf41506183e9e49dfb54d5063796dfa0d403a4deccfa'));
        expect(parsed.s.toString(), equals('21463938592353267769710297084836796652964571266930856168996063301532842380538'));
    });


    test('should parse this 68 byte signature', () {
        var sighex = '3042021e17cfe77536c3fb0526bd1a72d7a8e0973f463add210be14063c8a9c37632022061bfa677f825ded82ba0863fb0c46ca1388dd3e647f6a93c038168b59d131a51';
        var parsed = SVSignature.fromDER(sighex);
//      parsed.header.should.equal(0x30)
//      parsed.length.should.equal(66)
//      parsed.rlength.should.equal(30)
//      parsed.rneg.should.equal(false)
        expect(parsed.rHex, equals('17cfe77536c3fb0526bd1a72d7a8e0973f463add210be14063c8a9c37632'));
//      expect(parsed.r.toString(), equals('164345250294671732127776123343329699648286106708464198588053542748255794'));
//      parsed.slength.should.equal(32)
//      parsed.sneg.should.equal(false)
        expect(parsed.sHex, equals('61bfa677f825ded82ba0863fb0c46ca1388dd3e647f6a93c038168b59d131a51'));
        expect(parsed.s.toString(), equals('44212963026209759051804639008236126356702363229859210154760104982946304432721'));
    });


    //probably a spooky signature
    test('should parse this signature from script_valid.json', () {
        var sighex = '304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef051';
        var parsed = SVSignature.fromDER(sighex);
        expect(parsed, isNotNull);
    });


    test('should convert these known r and s values into a known signature', () {
        var r = BigInt.parse('63173831029936981022572627018246571655303050627048489594159321588908385378810');
        var s = BigInt.parse('4331694221846364448463828256391194279133231453999942381442030409253074198130');
        var sig = SVSignature.fromECParams(r, s);
        var der = sig.toDER();

        expect(HEX.encode(der), equals(
            '30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72'));
    });


    test('should convert this signature in to hex DER', () {
        var r = BigInt.parse('63173831029936981022572627018246571655303050627048489594159321588908385378810');
        var s = BigInt.parse('4331694221846364448463828256391194279133231453999942381442030409253074198130');
        var sig = SVSignature.fromECParams(r, s);
        var hex = sig.toString();
        expect(hex, equals(
            '30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72'));
    });

    test('should know this is a DER signature', () {
        var sighex = '3042021e17cfe77536c3fb0526bd1a72d7a8e0973f463add210be14063c8a9c37632022061bfa677f825ded82ba0863fb0c46ca1388dd3e647f6a93c038168b59d131a5101';
        expect(SVSignature.isTxDER(sighex), isTrue);
    });

    test('should know this is not a DER signature', () {
        // for more extensive tests, see the script interpreter
        var sighex = '3142021e17cfe77536c3fb0526bd1a72d7a8e0973f463add210be14063c8a9c37632022061bfa677f825ded82ba0863fb0c46ca1388dd3e647f6a93c038168b59d131a5101';
        expect(SVSignature.isTxDER(sighex), isFalse);
    });

//    test('canonical signatures for bitcoind ', () async {
//            await File("${Directory.current.path}/test/data/bitcoind/sig_canonical.json")
//                .readAsString()
//                .then((contents) => jsonDecode(contents))
//                .then((jsonData) {
//                List.from(jsonData).forEach((sig) {
//                    var flags = Interpreter.SCRIPT_VERIFY_DERSIG | Interpreter.SCRIPT_VERIFY_STRICTENC;
//                    var result = Interpreter.checkSignatureEncoding(sig, flags);
//                    expect(result, isTrue);
//                });
//            });
//    });


    //FIXME: Non-Canonical sigs don't all validate.
//    test('non-canonical signatures for bitcoind ', () async {
//        await File("${Directory.current.path}/test/data/bitcoind/sig_noncanonical.json")
//            .readAsString()
//            .then((contents) => jsonDecode(contents))
//            .then((jsonData) {
//            List.from(jsonData).forEach((vector) {
//                var flags = Interpreter.SCRIPT_VERIFY_DERSIG | Interpreter.SCRIPT_VERIFY_STRICTENC;
//                var result = Interpreter.checkSignatureEncoding(vector[1], flags);
//                expect(result, isFalse);
//            });
//        });
//    });

    test('should reject invalid sighash types and accept valid ones', () {
      var sig = SVSignature();
      expect(sig.hasDefinedHashtype(), isFalse);
      var testCases = [
        [null, false],
        [0, false],
        [-1, false],
        [SighashType.SIGHASH_ANYONECANPAY, false],
        [SighashType.SIGHASH_ANYONECANPAY | SighashType.SIGHASH_ALL, true],
        [SighashType.SIGHASH_ANYONECANPAY | SighashType.SIGHASH_NONE, true],
        [SighashType.SIGHASH_ANYONECANPAY | SighashType.SIGHASH_SINGLE, true],
        [SighashType.SIGHASH_ALL, true],
        [SighashType.SIGHASH_NONE, true],
        [SighashType.SIGHASH_SINGLE, true],
        [SighashType.SIGHASH_SINGLE + 1, false],
        [(SighashType.SIGHASH_ANYONECANPAY | SighashType.SIGHASH_SINGLE) + 1, false],
        [(SighashType.SIGHASH_ANYONECANPAY | SighashType.SIGHASH_ALL) - 1, false]
      ];

      testCases.forEach((vector) {
        sig.nhashtype = vector[0];
        expect(sig.hasDefinedHashtype(), equals(vector[1]));

      });
    });


    test('should detect high and low S', () {
      var r = BigInt.parse('63173831029936981022572627018246571655303050627048489594159321588908385378810');

      var sig = SVSignature.fromECParams(r, BigInt.parse("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1", radix: 16));
      expect(sig.hasLowS(), isFalse);

      var sig2 = SVSignature.fromECParams(r, BigInt.parse('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', radix: 16));
      expect(sig2.hasLowS(), isTrue);

      var sig3 = SVSignature.fromECParams(r, BigInt.from(1));
      expect(sig3.hasLowS(), equals(true));

      var sig4 = SVSignature.fromECParams(r, BigInt.zero);
      expect(sig4.hasLowS(), equals(false));
    });


}
