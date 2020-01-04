import 'package:test/test.dart';
import 'package:twostack/src/exceptions.dart';
import 'package:twostack/src/hdpublickey.dart';


var xprivkey = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';
var xpubkey = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
var xpubkeyTestnet = 'tpubD6NzVbkrYhZ4WZaiWHz59q5EQ61bd6dUYfU4ggRWAtNAyyYRNWT6ktJ7UHJEXURvTfTfskFQmK7Ff4FRkiRN5wQH8nkGAb6aKB4Yyeqsw5m';
var json = '{"network":"livenet","depth":0,"fingerPrint":876747070,"parentFingerPrint":0,"childIndex":0,"chainCode":"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508","publicKey":"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2","checksum":-1421395167,"xpubkey":"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"}';
var derived01200000 = 'xpub6BqyndF6rkBNTV6LXwiY8Pco8aqctqq7tGEUdA8fmGDTnDJphn2fmxr3eM8Lm3m8TrNUsLbEjHvpa3adBU18YpEx4tp2Zp6nqax3mQkudhX';

main(){

    test('derivation is the same whether deriving with number or string', () {
        var pubkey = HDPublicKey.fromXpub(xpubkey);
        var derived1 = pubkey.deriveChildNumber(0).deriveChildNumber(1).deriveChildNumber(200000);
        var derived2 = pubkey.deriveChildKey('m/0/1/200000');
        expect(derived1.xpubkey, equals(derived01200000));
        expect(derived2.xpubkey, equals(derived01200000));
    });

    test('throws', () {
        expect(() => HDPublicKey.fromXpub(xpubkey).deriveChildKey('s'), throwsA(TypeMatcher<InvalidPathException>()));
    });

    test('toString() returns the same value as .xpubkey', () {
        var pubKey = HDPublicKey.fromXpub(xpubkey);
        expect(pubKey.toString(), equals(pubKey.xpubkey));
    });


//    test('allows special parameters m, M', () {
//        var expectDerivationSuccess = (argument) {
//            expect(HDPublicKey.fromXpub(xpubkey).deriveChildKey(argument).xpubkey, equals(xpubkey));
//        };
//      expectDerivationSuccess('m');
//      expectDerivationSuccess('M');
//    });



//    test('validates correct paths', () {
//        var valid;
//
//        valid = HDPublicKey.isValidPath('m/123/12');
//        valid.should.equal(true)
//
//        valid = HDPublicKey.isValidPath('m');
//        valid.should.equal(true)
//
//        valid = HDPublicKey.isValidPath(123);
//        valid.should.equal(true)
//    });


//    test('can\'t derive hardened keys', () {
//        expect(() => HDPublicKey.fromXpub(xpubkey).deriveChildKey(HDPublicKey.Hardened), throwsException);
//    });

    /*

    it('rejects illegal paths', function () {
      var valid

      valid = HDPublicKey.isValidPath('m/-1/12')
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath("m/0'/12")
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath('m/8000000000/12')
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath('bad path')
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath(-1)
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath(8000000000)
      valid.should.equal(false)

      valid = HDPublicKey.isValidPath(HDPublicKey.Hardened)
      valid.should.equal(false)
    })
     */
}

/*

describe('HDPublicKey interface', function () {
  var expectFail = function (func, errorType) {
    (function () {
      func()
    }).should.throw(errorType)
  }

  var expectDerivationFail = function (argument, error) {
    (function () {
      var pubkey = new HDPublicKey(xpubkey)
      pubkey.deriveChild(argument)
    }).should.throw(error)
  }

  var expectFailBuilding = function (argument, error) {
    (function () {
      return new HDPublicKey(argument)
    }).should.throw(error)
  }

  describe('creation formats', function () {

    describe('xpubkey string serialization errors', function () {
      it('fails on invalid length', function () {
        expectFailBuilding(
          Base58Check.encode(buffer.Buffer.from([1, 2, 3])),
          hdErrors.InvalidLength
        )
      })
      it('fails on invalid base58 encoding', function () {
        expectFailBuilding(
          xpubkey + '1',
          errors.InvalidB58Checksum
        )
      })
      it('user can ask if a string is valid', function () {
        (HDPublicKey.isValidSerialized(xpubkey)).should.equal(true)
      })
    })

    it('can be generated from a json', function () {
      expect(new HDPublicKey(JSON.parse(json)).xpubkey).to.equal(xpubkey)
    })

    it('can generate a json that has a particular structure', function () {
      assert(_.isEqual(
        new HDPublicKey(JSON.parse(json)).toJSON(),
        new HDPublicKey(xpubkey).toJSON()
      ))
    })

    it('builds from a buffer object', function () {
      (new HDPublicKey(new HDPublicKey(xpubkey)._buffers)).xpubkey.should.equal(xpubkey)
    })

    it('checks the checksum', function () {
      var buffers = new HDPublicKey(xpubkey)._buffers
      buffers.checksum = BufferUtil.integerAsBuffer(1)
      expectFail(function () {
        return new HDPublicKey(buffers)
      }, errors.InvalidB58Checksum)
    })
  })

  describe('error checking on serialization', function () {
    var compareType = function (a, b) {
      expect(a instanceof b).to.equal(true)
    }
    it('throws invalid argument when argument is not a string or buffer', function () {
      compareType(HDPublicKey.getSerializedError(1), hdErrors.UnrecognizedArgument)
    })
    it('if a network is provided, validates that data corresponds to it', function () {
      compareType(HDPublicKey.getSerializedError(xpubkey, 'testnet'), errors.InvalidNetwork)
    })
    it('recognizes invalid network arguments', function () {
      compareType(HDPublicKey.getSerializedError(xpubkey, 'invalid'), errors.InvalidNetworkArgument)
    })
    it('recognizes a valid network', function () {
      expect(HDPublicKey.getSerializedError(xpubkey, 'livenet')).to.equal(null)
    })
  })


  it('publicKey property matches network', function () {
    var livenet = new HDPublicKey(xpubkey)
    var testnet = new HDPublicKey(xpubkeyTestnet)

    livenet.publicKey.network.should.equal(Networks.livenet)
    testnet.publicKey.network.should.equal(Networks.testnet)
  })

  it('inspect() displays correctly', function () {
    var pubKey = new HDPublicKey(xpubkey)
    pubKey.inspect().should.equal('<HDPublicKey: ' + pubKey.xpubkey + '>')
  })

  describe('conversion to/from buffer', function () {
    it('should roundtrip to an equivalent object', function () {
      var pubKey = new HDPublicKey(xpubkey)
      var toBuffer = pubKey.toBuffer()
      var fromBuffer = HDPublicKey.fromBuffer(toBuffer)
      var roundTrip = new HDPublicKey(fromBuffer.toBuffer())
      roundTrip.xpubkey.should.equal(xpubkey)
    })
  })

  describe('conversion to/from hex', function () {
    it('should roundtrip to an equivalent object', function () {
      var pubKey = new HDPublicKey(xpubkey)
      var toHex = pubKey.toHex()
      var fromHex = HDPublicKey.fromHex(toHex)
      var roundTrip = new HDPublicKey(fromHex.toBuffer())
      roundTrip.xpubkey.should.equal(xpubkey)
    })
  })

  describe('from hdprivatekey', function () {
    var str = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    it('should roundtrip to/from a buffer', function () {
      var xprv1 = new HDPrivateKey(str)
      var xprv2 = HDPrivateKey.fromRandom()
      var xprv3 = HDPrivateKey.fromRandom()
      var xpub1 = HDPublicKey.fromHDPrivateKey(xprv1)
      var xpub2 = HDPublicKey.fromHDPrivateKey(xprv2)
      var xpub3 = HDPublicKey.fromHDPrivateKey(xprv3)
      xpub1.toString().should.equal('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
      xpub1.toString().should.not.equal(xpub2.toString())
      xpub1.toString().should.not.equal(xpub3.toString())
    })
  })

  describe('conversion to different formats', function () {
    var plainObject = {
      'network': 'livenet',
      'depth': 0,
      'fingerPrint': 876747070,
      'parentFingerPrint': 0,
      'childIndex': 0,
      'chainCode': '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
      'publicKey': '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
      'checksum': -1421395167,
      'xpubkey': 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    }
    it('roundtrips to JSON and to Object', function () {
      var pubkey = new HDPublicKey(xpubkey)
      expect(HDPublicKey.fromObject(pubkey.toJSON()).xpubkey).to.equal(xpubkey)
    })
    it('recovers state from Object', function () {
      new HDPublicKey(plainObject).xpubkey.should.equal(xpubkey)
    })
  })

  })
})
 */