
import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';
import 'package:twostack/src/address.dart';
import 'package:twostack/src/encoding/utils.dart';
import 'package:twostack/src/networks.dart';
import 'dart:convert';
import 'dart:io';

import 'package:twostack/src/privatekey.dart';
import 'package:twostack/src/publickey.dart';

final _domainParams = new ECDomainParameters('secp256k1');

main(){


    test ('we can perform a WIF key import', (){
        var wifKey = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ';
        var privateKey = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D';
        var privkey = new SVPrivateKey.fromWIF(wifKey);
        var decodedPrivKey = encodeBigInt(privkey.privateKey);

        expect(HEX.encode(decodedPrivKey).toUpperCase(),equals(privateKey));
    });

    test('can be instantiated from a hex string', (){
        var privhex = '906977a061af29276e40bf377042ffbde414e496ae2260bbf1fa9d085637bfff';
        var pubhex = '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc';
        var privkey = SVPrivateKey.fromHex(privhex, NetworkType.MAIN);
        expect(privkey.publicKey.getEncoded(true), equals(pubhex));
    });

    test('bitcoind compatibility assertions - should interpret WIF private keys correctly', () async {
        await File("${Directory.current.path}/test/data/bitcoind/base58_keys_valid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((item) {
                if (item[2]['isPrivkey']) {
                   var key = SVPrivateKey.fromWIF(item[0]);
                   var elemNet = item[2]['isTestnet'] ? NetworkType.TEST : NetworkType.MAIN;

                   expect(key.networkType, equals(elemNet));
                   expect(key.isCompressed, equals(item[2]['isCompressed']));
                    //TODO: test for compression ???

                }

            });
        });
    });

    test('bitcoind compatibility assertions - should throw exception on invalid keys', () async {
        await File("${Directory.current.path}/test/data/bitcoind/base58_keys_invalid.json")
            .readAsString()
            .then((contents) => jsonDecode(contents))
            .then((jsonData) {
            List.from(jsonData).forEach((item) {
                expect(() => SVPrivateKey.fromWIF(item[0]), throwsException);
            });
        });
    });

    test('should not be able to instantiate private key greater than N', (){
        expect(() => SVPrivateKey.fromBigInt(_domainParams.n), throwsException);
    });

    test('should throw an exception if WIF is too long', (){
        var wifKey = 'L3T1s1TYP9oyhHpXgkyLoJFGniEgkv2Jhi138d7R2yJ9F4QdDU2m';
        wifKey = wifKey + '1';
        expect(() => SVPrivateKey.fromWIF(wifKey), throwsException);
    });

    test('should not be able to instantiate private key WIF because of unknown network byte', (){
        var wifKey = 'L3T1s1TYP9oyhHpXgkyLoJFGniEgkv2Jhi138d7R2yJ9F4QdDU2m';
        var modKey = HEX.encode([0xff]) + wifKey.substring(1, wifKey.length) ;
        expect (() => SVPrivateKey.fromWIF(modKey), throwsException);
    });

    test('should not be able to create a zero private key', (){
        expect(() => SVPrivateKey.fromBigInt(BigInt.zero), throwsException);
    });

    test('should be able to render private key in WIF format', (){
        var wifLivenetUncompressed = '5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un';
        var privateKey = SVPrivateKey.fromWIF(wifLivenetUncompressed);

        expect(privateKey.toWIF(), equals(wifLivenetUncompressed));

    });

    test('should be able to create a mainnet private key', (){
        var hex = '96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a';
        var privateKey = SVPrivateKey.fromHex(hex, NetworkType.MAIN);

        var wifLivenet = 'L2Gkw3kKJ6N24QcDuH4XDqt9cTqsKTVNDGz1CRZhk9cq4auDUbJy';
        expect(privateKey.toWIF(), equals(wifLivenet));
//        var wifLivenetUncompressed = '5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un';
    });


    test('should output this known livenet address correctly', (){
        SVPrivateKey privateKey = SVPrivateKey.fromWIF('L3T1s1TYP9oyhHpXgkyLoJFGniEgkv2Jhi138d7R2yJ9F4QdDU2m');
        Address address = privateKey.toAddress();
        expect(address.toString(), equals('1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT'));
    });


    test('should output this known testnet address correctly', () {
        var privkey = SVPrivateKey.fromWIF('cR4qogdN9UxLZJXCNFNwDRRZNeLRWuds9TTSuLNweFVjiaE4gPaq');
        var address = privkey.toAddress();
        expect(address.toString(), equals('mtX8nPZZdJ8d3QNLRJ1oJTiEi26Sj6LQXS'));
    });

    test('should parse this compressed testnet address correctly', () {
        var wifLivenet = 'L2Gkw3kKJ6N24QcDuH4XDqt9cTqsKTVNDGz1CRZhk9cq4auDUbJy';
        var privkey = SVPrivateKey.fromWIF(wifLivenet);
        expect(privkey.toWIF(), equals(wifLivenet));
    });


    test('should parse this compressed testnet address correctly', () {
        var wifTestnet = 'cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG';
        var privkey = SVPrivateKey.fromWIF(wifTestnet);
        expect(privkey.toWIF(), equals(wifTestnet));
    });


    test('should parse this uncompressed testnet address correctly', () {
        var wifTestnetUncompressed = '92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu';
        var privkey = SVPrivateKey.fromWIF(wifTestnetUncompressed);
        expect(privkey.toWIF(), equals(wifTestnetUncompressed));
    });

    test('should parse this uncompressed livenet address correctly', () {
        var wifLivenetUncompressed = '5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un';
        SVPrivateKey privkey = SVPrivateKey.fromWIF(wifLivenetUncompressed);
        expect(privkey.toHex(), equals('96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a'));
    });

    test('creates an address as expected from WIF, livenet', () {
        SVPrivateKey privkey = SVPrivateKey.fromWIF('5J2NYGstJg7aJQEqNwYp4enG5BSfFdKXVTtBLvHicnRGD5kjxi6');
        expect(privkey.publicKey.toAddress(NetworkType.MAIN).toString(), equals('135bwugFCmhmNU3SeCsJeTqvo5ViymgwZ9'));
    });

    test('creates an address as expected from WIF, testnet', () {
        SVPrivateKey privkey = SVPrivateKey.fromWIF('92VYMmwFLXRwXn5688edGxYYgMFsc3fUXYhGp17WocQhU6zG1kd');
        expect(privkey.publicKey.toAddress(NetworkType.TEST).toString(), equals('moiAvLUw16qgrwhFGo1eDnXHC2wPMYiv7Y'));
    });


    test('should convert this known PrivateKey to known PublicKey', () {
        var privhex = '906977a061af29276e40bf377042ffbde414e496ae2260bbf1fa9d085637bfff';
        var pubhex = '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc';
        var privkey = SVPrivateKey.fromHex(privhex, NetworkType.TEST);
        var pubkey = privkey.publicKey;
        expect(pubkey.toString(), equals(pubhex));
    });


    test('should have a "publicKey" property', () {
        var privhex = '906977a061af29276e40bf377042ffbde414e496ae2260bbf1fa9d085637bfff';
        var pubhex = '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc';
        var privkey = SVPrivateKey.fromHex(privhex, NetworkType.TEST);
        expect(privkey.publicKey.toString(), equals(pubhex));
    });


    test('should convert this known PrivateKey to known PublicKey and preserve compressed=true', () {
        var privwif = 'L3T1s1TYP9oyhHpXgkyLoJFGniEgkv2Jhi138d7R2yJ9F4QdDU2m';
        var privkey = SVPrivateKey.fromWIF(privwif);
        SVPublicKey pubkey = privkey.publicKey;
        expect(pubkey.isCompressed, equals(true));
    });


    test('should convert this known PrivateKey to known PublicKey and preserve compressed=false', () {
        var privwif = '92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu';
        var privkey = SVPrivateKey.fromWIF(privwif);
        SVPublicKey pubkey = privkey.publicKey;
        expect(pubkey.isCompressed, equals(false));
    });
}

//    test('creates network specific address', () {
//        var pk = SVPrivateKey.fromWIF('cR4qogdN9UxLZJXCNFNwDRRZNeLRWuds9TTSuLNweFVjiaE4gPaq');
//
//
//        expect(pk.toAddress(networkType: NetworkType.MAIN).networkTypes, contains(NetworkType.MAIN));
//        expect(pk.toAddress(networkType: NetworkType.TEST).networkTypes, contains(NetworkType.TEST));
//    });

    /*

  })
     */


/*
'use strict'

var chai = require('chai')
var should = chai.should()
var expect = chai.expect

var bsv = require('..')
var BN = bsv.crypto.BN
var Point = bsv.crypto.Point
var PrivateKey = bsv.PrivateKey
var Networks = bsv.Networks
var Base58Check = bsv.encoding.Base58Check

var validbase58 = require('./data/bitcoind/base58_keys_valid.json')
var invalidbase58 = require('./data/bitcoind/base58_keys_invalid.json')

describe('PrivateKey', function () {
  var hex = '96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a'
  var hex2 = '8080808080808080808080808080808080808080808080808080808080808080'
  var buf = Buffer.from(hex, 'hex')
  var wifTestnet = 'cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG'
  var wifTestnetUncompressed = '92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu'
  var wifLivenet = 'L2Gkw3kKJ6N24QcDuH4XDqt9cTqsKTVNDGz1CRZhk9cq4auDUbJy'
  var wifLivenetUncompressed = '5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un'
  var wifNamecoin = '74pxNKNpByQ2kMow4d9kF6Z77BYeKztQNLq3dSyU4ES1K5KLNiz'

  it('should create a new random private key', function () {
    var a = new PrivateKey()
    should.exist(a)
    should.exist(a.bn)
    var b = PrivateKey()
    should.exist(b)
    should.exist(b.bn)
  })

  it('should create a privatekey from hexa string', function () {
    var a = new PrivateKey(hex2)
    should.exist(a)
    should.exist(a.bn)
  })

  it('should create a new random testnet private key with only one argument', function () {
    var a = new PrivateKey(Networks.testnet)
    should.exist(a)
    should.exist(a.bn)
  })

  it('should create a private key from a custom network WIF string', function () {
    var nmc = {
      name: 'namecoin',
      alias: 'namecoin',
      pubkeyhash: 0x34,
      privatekey: 0xB4,
      // these below aren't the real NMC version numbers
      scripthash: 0x08,
      xpubkey: 0x0278b20e,
      xprivkey: 0x0278ade4,
      networkMagic: 0xf9beb4fe,
      port: 20001,
      dnsSeeds: [
        'localhost',
        'mynet.localhost'
      ]
    }
    Networks.add(nmc)
    var nmcNet = Networks.get('namecoin')
    var a = new PrivateKey(wifNamecoin, nmcNet)
    should.exist(a)
    should.exist(a.bn)
    Networks.remove(nmcNet)
  })

  describe('#json/object', function () {
    it('should input/output json', function () {
      var json = JSON.stringify({
        bn: '96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a',
        compressed: false,
        network: 'livenet'
      })
      var key = PrivateKey.fromObject(JSON.parse(json))
      JSON.stringify(key).should.equal(json)
    })

    it('should input/output json', function () {
      var json = JSON.stringify({
        bn: '96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a',
        compressed: false,
        network: 'livenet'
      })
      var key = PrivateKey.fromJSON(JSON.parse(json))
      JSON.stringify(key).should.equal(json)
    })

    it('input json should correctly initialize network field', function () {
      ['livenet', 'testnet', 'mainnet'].forEach(function (net) {
        var pk = PrivateKey.fromObject({
          bn: '96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a',
          compressed: false,
          network: net
        })
        pk.network.should.be.deep.equal(Networks.get(net))
      })
    })

    it('fails on invalid argument', function () {
      expect(function () {
        return PrivateKey.fromJSON('¹')
      }).to.throw()
    })

    it('also accepts an object as argument', function () {
      expect(function () {
        return PrivateKey.fromObject(new PrivateKey().toObject())
      }).to.not.throw()
    })

    it('also accepts an object as argument', function () {
      expect(function () {
        return PrivateKey.fromObject(new PrivateKey().toJSON())
      }).to.not.throw()
    })
  })

  it('coverage: public key cache', function () {
    expect(function () {
      var privateKey = new PrivateKey()
      /* jshint unused: false */
      var publicKey = privateKey.publicKey
      return publicKey
    }).to.not.throw()
  })




  describe('#getValidationError', function () {
    it('should get an error because private key greater than N', function () {
      var n = Point.getN()
      var a = PrivateKey.getValidationError(n)
      a.message.should.equal('Number must be less than N')
    })

    it('should validate as false because private key greater than N', function () {
      var n = Point.getN()
      var a = PrivateKey.isValid(n)
      a.should.equal(false)
    })

    it('should recognize that undefined is an invalid private key', function () {
      PrivateKey.isValid().should.equal(false)
    })

    it('should validate as true', function () {
      var a = PrivateKey.isValid('L3T1s1TYP9oyhHpXgkyLoJFGniEgkv2Jhi138d7R2yJ9F4QdDU2m')
      a.should.equal(true)
    })
  })

  describe('buffer serialization', function () {
    it('returns an expected value when creating a PrivateKey from a buffer', function () {
      var privkey = new PrivateKey(BN.fromBuffer(buf), 'livenet')
      privkey.toHex().should.equal(buf.toString('hex'))
    })

    it('roundtrips correctly when using toBuffer/fromBuffer', function () {
      var privkey = new PrivateKey(BN.fromBuffer(buf))
      var toBuffer = new PrivateKey(privkey.toBuffer())
      var fromBuffer = PrivateKey.fromBuffer(toBuffer.toBuffer())
      fromBuffer.toHex().should.equal(privkey.toHex())
    })
  })

  describe('#toBigNumber', function () {
    it('should output known BN', function () {
      var a = BN.fromBuffer(buf)
      var privkey = new PrivateKey(a, 'livenet')
      var b = privkey.toBigNumber()
      b.toString('hex').should.equal(a.toString('hex'))
    })
  })

  describe('#fromRandom', function () {
    it('should set bn gt 0 and lt n, and should be compressed', function () {
      var privkey = PrivateKey.fromRandom()
      privkey.bn.gt(new BN(0)).should.equal(true)
      privkey.bn.lt(Point.getN()).should.equal(true)
      privkey.compressed.should.equal(true)
    })
  })


  describe('#toPublicKey', function () {
})
 */