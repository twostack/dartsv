import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';
import 'dart:convert';
import 'dart:io';


final _domainParams = new ECDomainParameters('secp256k1');

void main() {
    var invalidPoint = '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

    test('Empty compressed value constructor throws and exception', () {
        expect(() => SVPublicKey.fromHex(''),
            throwsA(TypeMatcher<BadParameterException>()));
    });

    test('errors if an invalid point is provided', () {
        expect(() => SVPublicKey.fromHex(invalidPoint),
            throwsA(TypeMatcher<InvalidPointException>()));
    });

    test('PublicKey instance can be created from a compressed public key ', () {
        var publicKeyHex = '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
        var publicKey = new SVPublicKey.fromHex(publicKeyHex);
        expect(publicKey.toString(), equals(publicKeyHex));
    });

    test(
        'PublicKey instance can be created from an uncompressed public key ', () {
        var publicKeyHex = '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341';
        var publicKey = new SVPublicKey.fromHex(publicKeyHex);
        expect(publicKey.toString(), equals(publicKeyHex));

        var pubx = encodeBigInt(publicKey.point.x!.toBigInteger()!);
        var puby = encodeBigInt(publicKey.point.y!.toBigInteger()!);
        expect(HEX.encode(pubx), equals('1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
        expect(HEX.encode(puby), equals('7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
    });


    test('should throw an exception when provided an invalid key ', () {
        var invalidHex = '091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
        expect(() => SVPublicKey.fromHex(invalidHex), throwsA(TypeMatcher<InvalidPointException>()));
    });

    test('should throw an exception when buffer is the incorrect length', () {
        var longHex = '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a34112';
        expect(() => SVPublicKey.fromHex(longHex), throwsA(TypeMatcher<InvalidPointException>()));
    });

    test('should be able to decode DER encoded public keys', () {
        var derHex = '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341';
        var pk = SVPublicKey.fromHex(derHex);

        var pubx = encodeBigInt(pk.point.x!.toBigInteger()!);
        var puby = encodeBigInt(pk.point.y!.toBigInteger()!);

        expect(HEX.encode(pubx), equals('1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
        expect(HEX.encode(puby), equals('7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
    });

    group('#fromDER', () {
        test('should parse this uncompressed public key', () {
            var pk = SVPublicKey.fromDER(HEX.decode(
                '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
            expect(pk.point.x!.toBigInteger()!.toRadixString(16), equals('1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
            expect(pk.point.y!.toBigInteger()!.toRadixString(16), equals('7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
        });

        test('should parse this compressed public key', () {
            var pk = SVPublicKey.fromDER(HEX.decode('031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
            expect(pk.point.x!.toBigInteger()!.toRadixString(16), equals('1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
            expect(pk.point.y!.toBigInteger()!.toRadixString(16), equals('7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
        });

        test('should throw an error on this invalid public key', () {
            expect(() => SVPublicKey.fromDER(HEX.decode('091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a')), throwsException);
        });
    });


    test('should be able to instantiate from this X coordinate', () {
        var hexX = '1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
        var pk = SVPublicKey.fromX(hexX, true);

        var pubx = encodeBigInt(pk.point.x!.toBigInteger()!);
        var puby = encodeBigInt(pk.point.y!.toBigInteger()!);

        expect(HEX.encode(pubx), equals('1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a'));
        expect(HEX.encode(puby), equals('7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341'));
    });

//    test('should be able to generate correct addresses from WIF Private Keys', () {
//        // see: https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp#L20
//
//        var data = [
//            ['5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj', '1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ'],
//            ['5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3', '1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ'],
//            ['Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw', '1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs'],
//            ['L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g', '1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs']
//        ];
//
//        data.forEach((elem) {
//            var privkey = new SVPrivateKey.fromWIF(elem[0]);
//            var pubkey = SVPublicKey.fromPrivateKey(privkey);
//            Address address = new Address(elem[1]);
////            Address address = pubkey.toAddress(privkey.networkType);
//
//            expect(address.toString(), equals(elem[1]));
//        });
//    });

    //TODO: Consider if this convenience feature is necessary
    //    test('PublicKey instance can be created from another public key', (){
    //        var publicKeyHex = '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
    //        var publicKey = SVPublicKey.fromHex(publicKeyHex);
    //        var publicKey2 = new PublicKey(publicKey);
    //        expect(publicKey, equals(publicKey2));
    //    });


    test('should output this known mainnet address correctly', () {
        var pk = SVPublicKey.fromHex('03c87bd0e162f26969da8509cafcb7b8c8d202af30b928c582e263dd13ee9a9781');
        var address = pk.toAddress(NetworkType.MAIN);
        expect(address.toString(), equals('1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT'));
    });

    test('should output this known testnet address correctly', () {
        var pk = SVPublicKey.fromHex('0293126ccc927c111b88a0fe09baa0eca719e2a3e087e8a5d1059163f5c566feef');
        var address = pk.toAddress(NetworkType.TEST);
        expect(address.toString(), equals('mtX8nPZZdJ8d3QNLRJ1oJTiEi26Sj6LQXS'));
    });

    /*
    G: encoded (uncompressed) - 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    G: encoded (compressed) - 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
     */
    test(
        'PublicKey instance can be created from an uncompressed public key', () {
        var publicKeyHex = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'; //G
        var publicKey = new SVPublicKey.fromHex(publicKeyHex);
        expect(publicKey.getEncoded(false), equals(publicKeyHex));
    });

    test('throws an exception if a point not on the secp256k1 curve is provided', () {
        expect(() => SVPublicKey.fromXY(BigInt.from(1000), BigInt.from(1000)), throwsA(TypeMatcher<InvalidPointException>()));
    });

    test('can create a publicKey from the provided Private Key', () {
        var privhex = '906977a061af29276e40bf377042ffbde414e496ae2260bbf1fa9d085637bfff';
        var pubhex = '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc';

        var bignum = BigInt.parse(privhex, radix: 16);
        var privkey = SVPrivateKey.fromBigInt(bignum);
        var pubkey = SVPublicKey.fromPrivateKey(privkey);
        expect(pubkey.getEncoded(true), equals(pubhex));
    });

    test('we can handle problematic secp256k1 keys', () {
        var knownKeys = [
            {
                'wif': 'KzsjKq2FVqVuQv2ueHVFuB65A9uEZ6S1L6F8NuokCrE3V3kE3Ack',
                'priv': '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
                'pub': '03d6106302d2698d6a41e9c9a114269e7be7c6a0081317de444bb2980bf9265a01',
                'pubx': 'd6106302d2698d6a41e9c9a114269e7be7c6a0081317de444bb2980bf9265a01',
                'puby': 'e05fb262e64b108991a29979809fcef9d3e70cafceb3248c922c17d83d66bc9d'
            },
            {
                'wif': 'L5MgSwNB2R76xBGorofRSTuQFd1bm3hQMFVf3u2CneFom8u1Yt7G',
                'priv': 'f2cc9d2b008927db94b89e04e2f6e70c180e547b3e5e564b06b8215d1c264b53',
                'pub': '03e275faa35bd1e88f5df6e8f9f6edb93bdf1d65f4915efc79fd7a726ec0c21700',
                'pubx': 'e275faa35bd1e88f5df6e8f9f6edb93bdf1d65f4915efc79fd7a726ec0c21700',
                'puby': '367216cb35b086e6686d69dddd822a8f4d52eb82ac5d9de18fdcd9bf44fa7df7'
            }
        ];

        for (var i = 0; i < knownKeys.length; i++) {
            var privkey = new SVPrivateKey.fromWIF(knownKeys[i]['wif'] as String);
            var pubkey = SVPublicKey.fromPrivateKey(privkey);
            var decodedPrivKey = encodeBigInt(privkey.privateKey);
            var hexPrivKey = HEX.encode(decodedPrivKey);

            var pubx = encodeBigInt(pubkey.point.x!.toBigInteger()!);
            var puby = encodeBigInt(pubkey.point.y!.toBigInteger()!);

            expect(pubkey.getEncoded(true), equals(knownKeys[i]['pub']));
            expect(HEX.encode(pubx), equals(knownKeys[i]['pubx']));
            expect(HEX.encode(puby), equals(knownKeys[i]['puby']));
        }
    });


    test('can successfully create an instance a valid point', () {
        var pointX = '86a80a5a2bfc48dddde2b0bd88bd56b0b6ddc4e6811445b175b90268924d7d48';
        var pointY = '3b402dfc89712cfe50963e670a0598e6b152b3cd94735001cdac6794975d3afd';
        var pk = SVPublicKey.fromXY(BigInt.parse(pointX, radix: 16), BigInt.parse(pointY, radix: 16));

        expect(pk.point.x!.toBigInteger(), equals(BigInt.parse(pointX, radix: 16)));
        expect(pk.point.y!.toBigInteger(), equals(BigInt.parse(pointY, radix: 16)));
    });


    test('should not have an error if pubkey is valid', () {
        var hex = '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
        var pk = SVPublicKey.fromHex(hex);
    });

    //invalid y value for curve
    test('should throw an error if pubkey is invalid', () {
        var hex = '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a0000000000000000000000000000000000000000000000000000000000000000';
        expect(() => SVPublicKey.fromHex(hex), throwsException);
    });


    //invalid y value for curve
    test('should throw an error if pubkey is invalid', () {
        var hex = '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a00000000000000000000000000000000000000000000000000000000000000FF';
        expect(() => SVPublicKey.fromHex(hex), throwsException);
    });


    test('should print this known public key', () {
        var hex = '031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a';
        var pk = SVPublicKey.fromHex(hex);
        expect(pk.toString(), equals(hex));
    });


    //   this would be an interesting test, however point is itself null when trying
    //   to multiply in this way.
    //    test('should throw an error if pubkey is infinity', () {
    //        var point = _domainParams.G * _domainParams.n;
    //        expect(() => SVPublicKey.fromXY(point.x.toBigInteger(), point.y.toBigInteger()), throwsException);
    //    });

}
