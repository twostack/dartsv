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

    test('can sign a message', () {
        var message2 = new Message(utf8.encode(text));
        var signature2 = message2.sign(privateKey);
        var signature3 = Message(utf8.encode(text)).sign(privateKey);
        expect(signature2, isNotNull);
        expect(signature3, isNotNull);
    });

    test('can sign a message (buffer representation of utf-8 string)', () {
        var addr = new Address('n1ZCYg9YXtB5XCZazLxSmPDa8iwJRZHhGx');
        var messageBuf = new Message(utf8.encode(textBuffer));
        var signatureBuffer1 = messageBuf.sign(privateKey);
        expect(signatureBuffer1, isNotNull);
        expect(messageBuf.verifyFromAddress(addr, signatureBuffer1), isTrue);
    });


    test('can sign a message (buffer representation of arbitrary data)', () {
        Message messageBuf = new Message(base64Decode(bufferData));
        String signatureBuffer1 = messageBuf.sign(privateKey);
        String signatureBuffer2 = Message(base64Decode(bufferData)).sign(privateKey);
        expect(signatureBuffer1, isNotNull);
        expect(signatureBuffer2, isNotNull);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer1), isTrue);
        expect(messageBuf.verifyFromAddress(address, signatureBuffer2), isTrue);
    });

    test('can verify a message with signature', () {
        var message2 = new Message(utf8.encode(text));
        var signature2 = message2.sign(privateKey);
        Message message4 = new Message(utf8.encode(text));
        expect(message4.verifyFromPublicKey(publicKey, signature2), isTrue);
    });


    test('can verify a message with existing signature', () {
        var message5 = new Message(utf8.encode(text));
        expect(message5.verifyFromPublicKey(publicKey, signature), isTrue);
    });


    test('verify will correctly identify a bad signature', () {
        var message8 = new Message(utf8.encode(text));
        expect(message8.verifyFromPublicKey(publicKey, badSignature), isFalse);
    });


    test('can verify a message with address and generated signature string', () {
        var message9 = new Message(utf8.encode(text));
        var signature3 = Message(utf8.encode(text)).sign(privateKey);
        expect(message9.verifyFromAddress(address, signature3), isTrue);
    });


    test('will not verify with address mismatch', () {
        var message10 = new Message(utf8.encode(text));
        expect(message10.verifyFromAddress(badAddress, signatureString), isFalse);
    });


    test('will verify with an uncompressed pubkey using verifyFromPublicKey()', () {
        var privateKey = SVPrivateKey.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss');
        var message = new Message(utf8.encode('This is an example of a signed message.'));
        var signature = message.sign(privateKey);
        expect(message.verifyFromPublicKey(privateKey.publicKey, signature), isTrue);
    });

    test('will verify with an uncompressed pubkey using verifyFromAddress()', () {
        var privateKey = SVPrivateKey.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss');
        var message = new Message(utf8.encode('This is an example of a signed message.'));
        var signature = message.sign(privateKey);
        expect(message.verifyFromAddress(privateKey.toAddress(), signature), isTrue);
    });

    test('should sign and verify', () {
        var privateKey = SVPrivateKey.fromWIF('L3nrwRssVKMkScjejmmu6kmq4hSuUApJnFdW1hGvBP69jnQuKYCh');
        var address = privateKey.toAddress();
        var messageToSign = utf8.encode('this is the message that I want to sign');
        var message = Message(messageToSign);
        var signature = message.sign(privateKey);
        expect(signature.toString(), equals('II5uoh3m0yQ+/5va+1acFQhPaEdTnFFiG/PiKpoC+kpgHbmIk3aWHQ6tyPGgNCUmKlSfwzcP6qVAxuUt0PwDzpg='));
        expect(message.verifyFromAddress(address, signature), isTrue);
    });

    /*
  it('can chain methods', function () {
    var verified = Message(text).verify(address, signatureString)
    verified.should.equal(true)
  })
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






  describe('@sign', function () {
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
