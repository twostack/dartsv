import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/p2ms_builder.dart';
import 'package:test/test.dart';
import 'dart:convert';
import 'dart:io';

void main() {
    // livenet valid
    var PKHLivenet = [
        '15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2',
        '1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT',
        '1BpbpfLdY7oBS9gK7aDXgvMgr1DPvNhEB2',
        '1Jz2yCRd5ST1p2gUqFB5wsSQfdm3jaFfg7',
        '    1Jz2yCRd5ST1p2gUqFB5wsSQfdm3jaFfg7   \t\n'
    ];

    // livenet p2sh
    var P2SHLivenet = [
        '342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey',
        '33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk',
        '37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3',
        '3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy',
        '\t3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy \n \r'
    ];

    // testnet p2sh
    var P2SHTestnet = [
        '2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C',
        '2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda',
        '2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN',
        '2NB72XtkjpnATMggui83aEtPawyyKvnbX2o'
    ];

    // livenet bad checksums
    var badChecksums = [
        '15vkcKf7gB23wLAnZLmbVuMiiVDc3nq4a2',
        '1A6ut1tWnUq1SEQLMr4ttDh24wcbj4w2TT',
        '1BpbpfLdY7oBS9gK7aDXgvMgr1DpvNH3B2',
        '1Jz2yCRd5ST1p2gUqFB5wsSQfdmEJaffg7'
    ];

    // livenet non-base58
    var nonBase58 = [
        '15vkcKf7g#23wLAnZLmb\$uMiiVDc3nq4a2',
        '1A601ttWnUq1SEQLMr4ttDh24wcbj4w2TT',
        '1BpbpfLdY7oBS9gK7aIXgvMgr1DpvNH3B2',
        '1Jz2yCRdOST1p2gUqFB5wsSQfdmEJaffg7'
    ];

    // testnet valid
    var PKHTestnet = [
        'n28S35tqEMbt6vNad7A5K3mZ7vdn8dZ86X',
        'n45x3R2w2jaSC62BMa9MeJCd3TXxgvDEmm',
        'mursDVxqNQmmwWHACpM9VHwVVSfTddGsEM',
        'mtX8nPZZdJ8d3QNLRJ1oJTiEi26Sj6LQXS'
    ];

    var pubkeyhash = '3c3fa3d4adcaf8f52d5b1843975e122548269937'; //library expects this to be a byte array
    //  var buf = Buffer.concat([Buffer.from([0]), pubkeyhash])
    //  var str = '16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r'

    test(
        'accurately parses base58 public keys to conform with bitcoind specifications', () async {
        await File("${Directory.current.path}/test/data/bitcoind/base58_keys_valid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((item) {
                if (!item[2]['isPrivkey']) {
                    var address = new Address(item[0]);
                    expect(address.pubkeyHash160, equals(item[1]));

                    var networkType = item[2]['isTestnet'] ? NetworkType.TEST : NetworkType.MAIN;
                    expect(address.networkTypes, contains(networkType));

                    if (item[2]['addrType'] != null) {
                        var addrType = item[2]['addrType'];
                        switch (addrType) {
                            case 'script' :
                                expect(address.addressType, equals(AddressType.SCRIPT_HASH));
                                break;
                            case 'pubkey' :
                                expect(address.addressType, equals(AddressType.PUBKEY_HASH));
                                break;
                        }
                    }
                }
            });
        });
    });

    test('throws exceptions when seeing invalid addresses', () async {
        await File("${Directory.current.path}/test/data/bitcoind/base58_keys_invalid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((item) {
                expect(() => Address.fromBase58(item[0]), throwsA(TypeMatcher<AddressFormatException>()));
            });
        });
    });

    test('toString() method should render actual address', () {
        var str = '13k3vneZ3yvZnc9dNWYH2RJRFsagTfAERv';
        var address = new Address(str);
        expect(address.toBase58(), equals(str));
    });

    test('toString() should produce correct scripthash address', () {
      var address = Address(P2SHLivenet[0]);
      expect(address.toString(), equals(P2SHLivenet[0]));
    });

    test('toString() method should produce correct testnet scripthash address', () {
      var address = Address(P2SHTestnet[0]);
      expect(address.toString(), equals(P2SHTestnet[0]));
    });

    test('invalid checksums in addresses throw exception', () {
        for (var i = 0; i < badChecksums.length; i++) {
            expect(() => new Address(badChecksums[i]), throwsA(TypeMatcher<BadChecksumException>()));
        }
    });

    test('testnet addresses are recognised and accepted', () {
        for (var i = 0; i < PKHTestnet.length; i++) {
            var address = new Address(PKHTestnet[i]);
            expect(address.networkTypes, contains(NetworkType.TEST));
        }
    });

    test('addresses with whitespaces are recognised and accepted', () {
        var ws = '  \r \t    \n 1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT \t \n            \r';
        var address = new Address(ws);
        expect(address.toBase58(), equals('1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT'));
    });


    test('should derive mainnet address from private key', () {
        SVPrivateKey privateKey = new SVPrivateKey();
        var publicKey = SVPublicKey.fromPrivateKey(privateKey);
        var address = publicKey.toAddress(privateKey.networkType);
        expect(address.toString()[0], equals('1'));
    });

    test('should derive testnet address from private key', () {
        var privateKey = new SVPrivateKey(networkType: NetworkType.TEST);
        var publicKey = SVPublicKey.fromPrivateKey(privateKey);
        var address = publicKey.toAddress(NetworkType.TEST);

        expect([ 'm', 'n'], contains(address.toString()[0]));
    });

    test('should derive from this known address string livenet scripthash', () {
      var a = Address(P2SHLivenet[0]);
      var b = Address(a.toString());
      expect(b.toString(), equals(P2SHLivenet[0]));
    });

    test('should derive from this known address string testnet scripthash', () {
      var address = Address(P2SHTestnet[0]);
      address = Address(address.toString());
      expect(address.toString(), equals(P2SHTestnet[0]));
    });


    test('should make this address from a compressed pubkey', () {
        var pubkey = new SVPublicKey.fromHex('0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004');
        var address = pubkey.toAddress(NetworkType.MAIN);
        expect(address.toString(), equals('19gH5uhqY6DKrtkU66PsZPUZdzTd11Y7ke'));
    });


    test('validates correctly the P2SH test vector', () {
        for (var i = 0; i < P2SHLivenet.length; i++) {
            expect(() => Address(P2SHLivenet[i]), returnsNormally);
        }
    });

    test('validates correctly the P2SH testnet test vector', () {
        for (var i = 0; i < P2SHTestnet.length; i++) {
            expect(() => Address(P2SHTestnet[i]), returnsNormally);
        }
    });


    test('should detect a P2SH livenet address', () {
        var address = Address(P2SHLivenet[0]);
        expect(address.networkType, equals(NetworkType.MAIN));
        expect(address.addressType, equals(AddressType.SCRIPT_HASH));
    });

    test('should detect a P2SH testnet address', () {
        var address = Address(P2SHTestnet[0]);
        expect(address.networkType, equals(NetworkType.TEST));
        expect(address.addressType, equals(AddressType.SCRIPT_HASH));
    });

  group('creating a P2SH address from Script', () {
    var public1 = '02da5798ed0c055e31339eb9b5cef0d3c0ccdec84a62e2e255eb5c006d4f3e7f5b';
    var public2 = '0272073bf0287c4469a2a011567361d42529cd1a72ab0d86aa104ecc89342ffeb0';
    var public3 = '02738a516a78355db138e8119e58934864ce222c553a5407cf92b9c1527e03c1a2';
    var publics = [public1, public2, public3];

    var pubkeyList = publics.map((key) => SVPublicKey.fromHex(key)).toList();
    var lockBuilder = P2MSLockBuilder(pubkeyList, 2);
    var script = lockBuilder.getScriptPubkey();

    test('can create an address from a set of public keys', () {
        var address = Address.fromScript(script, NetworkType.MAIN);
        expect(address.toString(), equals('3FtqPRirhPvrf7mVUSkygyZ5UuoAYrTW3y'));
    });

    test('works on testnet also', () {
      var address = Address.fromScript(script, NetworkType.TEST);
      expect(address.toString(), equals('2N7T3TAetJrSCruQ39aNrJvYLhG1LJosujf'));
    });

  });

  test('should make this address from a compressed pubkey', () {
      var pubkey = SVPublicKey.fromHex('0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004');
      var address = Address.fromPublicKey(pubkey, NetworkType.MAIN);
      expect(address.toString(), equals('19gH5uhqY6DKrtkU66PsZPUZdzTd11Y7ke'));
  });

  test('should make this address from an uncompressed pubkey', () {
      var pubkey = SVPublicKey.fromHex('0485e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b00' +
          '4833fef26c8be4c4823754869ff4e46755b85d851077771c220e2610496a29d98');
      var address = Address.fromPublicKey(pubkey, NetworkType.MAIN);
      expect(address.toString(), equals('16JXnhxjJUhxfyx4y6H4sFcxrgt8kQ8ewX'));
  });

  test('should create an address from Public Key Hash (PKH)',(){
      var pubkeyHash = '3c3fa3d4adcaf8f52d5b1843975e122548269937';
      var address = Address.fromPubkeyHash(pubkeyHash, NetworkType.MAIN);

      expect(address.toBase58(), equals("16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r"));
  });

}

