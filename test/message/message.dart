import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';


main() {
    var address = Address('n1ZCYg9YXtB5XCZazLxSmPDa8iwJRZHhGx');
    var badAddress = Address('mmRcrB5fTwgxaFJmVLNtaG8SV454y1E3kC');
    var privateKey = SVPrivateKey.fromWIF('cPBn5A4ikZvBTQ8D7NnvHZYCAxzDZ5Z2TSGW2LkyPiLxqYaJPBW4');
    var text = 'hello, world';
    var textBuffer = 'hello, world';
    var bufferData = 'H/DIn8uA1scAuKLlCx+/9LnAcJtwQQ0PmcPrJUq90aboLv3fH5fFvY+vmbfOSFEtGarznYli6ShPr9RXwY9UrIY=';
    var signatureString = 'H/DIn8uA1scAuKLlCx+/9LnAcJtwQQ0PmcPrJUq90aboLv3fH5fFvY+vmbfOSFEtGarznYli6ShPr9RXwY9UrIY=';

    var badSignatureString = 'H69qZ4mbZCcvXk7CWjptD5ypnYVLvQ3eMXLM8+1gX21SLH/GaFnAjQrDn37+TDw79i9zHhbiMMwhtvTwnPigZ6k=';

//    var signature = SVSignature.fromBase64(signatureString);
//    var badSignature = SVSignature.fromBase64(badSignatureString);

    var signature = signatureString;
    var badSignature = badSignatureString;
    var publicKey = privateKey.publicKey;

    var random = new Random.secure();
    final _secureRandom = new FortunaRandom();


    Uint8List _seed() {
        var random = Random.secure();
        var seed = List<int>.generate(32, (_) => random.nextInt(256));
        return Uint8List.fromList(seed);
    }

    test('can sign a message', () {
        var message2 = new Message(utf8.encode(text));
        var signature2 = message2.sign(privateKey);
        var signature3 = Message(utf8.encode(text)).sign(privateKey);
        expect(signature2, isNotNull);
        expect(signature3, isNotNull);
    });

    /* This test is unreliable at the moment because of exception handling inside test.
       Figure out a better way to test this !
       Hint: Occasionally fails with "Unable to find valid recovery factor error" :/

    test('Public Key Recovery test', (){

        var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
        _secureRandom.seed(KeyParameter(_seed()));

        var generator = ECKeyGenerator();
        generator.init(ParametersWithRandom(keyParams, _secureRandom));

        var keypair = generator.generateKeyPair();

        ECPrivateKey privateKey = keypair.privateKey;
        ECPublicKey publicKey = keypair.publicKey;

        var messageBuf = new Message(textBuffer);
        var derSig = messageBuf.sign(SVPrivateKey.fromBigInt(privateKey.d));

        var bFoundKey = false;
        SVSignature sig = SVSignature.fromDER(derSig);
        for (int i = 0; i < 4; i++) {
            var pubKey;
            try {
                pubKey = sig.recoverablePublicKey(i, messageBuf.magicHash());
            }catch(e){
                continue;
            }

            expect(pubKey.Q, equals(publicKey.Q));
            bFoundKey = true;
        }

        expect(bFoundKey, true);

    });
    */

    test('can sign a message (buffer representation of utf-8 string)', () {
        var messageBuf = new Message(utf8.encode(textBuffer));
        var signatureBuffer1 = messageBuf.sign(privateKey);
        var signatureBuffer2 = Message(utf8.encode(textBuffer)).sign(privateKey);
        expect(signatureBuffer1, isNotNull);
        expect(signatureBuffer2, isNotNull);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer1), isTrue);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer2), isTrue);
    });


    test('can sign a message (buffer representation of arbitrary data)', () {
        var messageBuf = new Message(base64Decode(bufferData));
        var signatureBuffer1 = messageBuf.sign(privateKey);
        var signatureBuffer2 = Message(base64Decode(bufferData)).sign(privateKey);
        expect(signatureBuffer1, isNotNull);
        expect(signatureBuffer2, isNotNull);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer1), isTrue);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer2), isTrue);
    });
    /*

    test('can verify a message with signature', () {
        var message2 = new Message(text);
        var signature2 = message2.sign(privateKey);

        var message4 = new Message(text);
        expect(message4.verifyFromPublicKey(publicKey, signature2), isTrue);
    });


    test('can verify a message with existing signature', () {
        var message5 = new Message(text);
        expect(message5.verifyFromPublicKey(publicKey, signature), isTrue);
    });


    test('verify will correctly identify a bad signature', () {
        var message8 = new Message(text);
        expect(message8.verifyFromPublicKey(publicKey, badSignature), isFalse);
//    should.exist(message8.error);
    });

     */
}


/*
'use strict'

var chai = require('chai')
var expect = chai.expect
var should = chai.should()

var bsv = require('../../')
var Address = bsv.Address
var Signature = bsv.crypto.Signature
var PrivateKey = bsv.PrivateKey
var Message = require('../../lib/message')

describe('Message', function () {

  var signature2
  var signature3


  it('can verify a message with address and generated signature string', function () {
    var message9 = new Message(text)
    var verified = message9.verify(address, signature3)
    should.not.exist(message9.error)
    verified.should.equal(true)
  })

  it('will not verify with address mismatch', function () {
    var message10 = new Message(text)
    var verified = message10.verify(badAddress, signatureString)
    should.exist(message10.error)
    verified.should.equal(false)
  })

  it('will verify with an uncompressed pubkey', function () {
    var privateKey = new bsv.PrivateKey('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
    var message = new Message('This is an example of a signed message.')
    var signature = message.sign(privateKey)
    var verified = message.verify(privateKey.toAddress(), signature)
    verified.should.equal(true)
  })

  it('can chain methods', function () {
    var verified = Message(text).verify(address, signatureString)
    verified.should.equal(true)
  })

  describe('@sign', function () {
    it('should sign and verify', function () {
      var privateKey = PrivateKey.fromString('L3nrwRssVKMkScjejmmu6kmq4hSuUApJnFdW1hGvBP69jnQuKYCh')
      var address = privateKey.toAddress()
      var message = 'this is the message that I want to sign'
      var sig = Message.sign(message, privateKey)
      sig.toString().should.equal('II5uoh3m0yQ+/5va+1acFQhPaEdTnFFiG/PiKpoC+kpgHbmIk3aWHQ6tyPGgNCUmKlSfwzcP6qVAxuUt0PwDzpg=')
      var verify = Message.verify(message, address, sig)
      verify.should.equal(true)
    })
  })

  describe('#json', function () {
    it('roundtrip to-from-to', function () {
      var json = new Message(text).toJSON()
      var message = Message.fromJSON(json)
      message.toString().should.equal(Buffer.from(text).toString())
    })

    it('checks that the string parameter is valid JSON', function () {
      expect(function () {
        return Message.fromJSON('¹')
      }).to.throw()
    })
  })

  describe('#toString', function () {
    it('message string', function () {
      var message = new Message(text)
      message.toString().should.equal(text)
    })

    it('roundtrip to-from-to', function () {
      var str = new Message(text).toString()
      var message = Message.fromString(str)
      message.toString().should.equal(text)
    })
  })

  describe('#inspect', function () {
    it('should output formatted output correctly', function () {
      var message = new Message(text)
      var output = '<Message: ' + text + '>'
      message.inspect().should.equal(output)
    })
  })

  it('accepts Address for verification', function () {
    var verified = Message(text)
      .verify(new Address(address), signatureString)
    verified.should.equal(true)
  })
})


 */
