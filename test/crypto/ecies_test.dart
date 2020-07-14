import 'dart:convert';

import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';
import 'package:dartsv/dartsv.dart';

main(){
  final alicePrivKey = SVPrivateKey.fromWIF('L1Ejc5dAigm5XrM3mNptMEsNnHzS7s51YxU7J61ewGshZTKkbmzJ');
  final bobPrivKey = SVPrivateKey.fromWIF('KxfxrUXSMjJQcb3JgnaaA6MqsrKQ1nBSxvhuigdKRyFiEm6BZDgG');
  final SHA256Digest _sha256Digest = SHA256Digest();

  test('throws an exception if not BIE1 buffer', (){

    final message = 'attack at dawn';
    final buffer = utf8.encode(message);

    expect(() => Ecies().AESDecrypt(buffer, alicePrivKey), throwsException);
  });

  test('throws exception if not BIE1 buffer', (){
    final magic = 'BIR1';
    final pubkeyBuffer = HEX.decode(alicePrivKey.publicKey.getEncoded(true));
    final buffer = utf8.encode(magic) + pubkeyBuffer;

    expect(() => Ecies().AESDecrypt(buffer, alicePrivKey), throwsException);
  });

  test('throws exception if public key decoding fails', (){
    final magic = 'BIE1';
    final pubkeyBuffer = HEX.decode(alicePrivKey.publicKey.getEncoded(true));
    final buffer = utf8.encode(magic) + [0,2,3,4] + pubkeyBuffer;

    expect(() => Ecies().AESDecrypt(buffer, alicePrivKey), throwsException);
  });


  test('throws exception if BIE1 checksum fails to validate', (){
    final magic = 'BIE1';
    final pubkeyBuffer = HEX.decode(alicePrivKey.publicKey.getEncoded(true));

    final message = 'just a plain text message. padded with some more gobbledygook just to make sure we have size';
    final sha256Hmac = HMac(_sha256Digest, 32);
    final checkSum = sha256Hmac.process(utf8.encode(message));

    final buffer = utf8.encode(magic) + pubkeyBuffer + utf8.encode(message); // + checkSum; no checksum
    expect(() => Ecies().AESDecrypt(buffer, alicePrivKey), throwsException);

  });

  test('returns normally if checksum validates', (){
    final magic = 'BIE1';
    final pubkeyBuffer = HEX.decode(alicePrivKey.publicKey.getEncoded(true));

    final message = 'just a plain text message. padded with some more gobbledygook just to make sure we have size';
    final sha256Hmac = HMac(_sha256Digest, 32);
    final checkSum = sha256Hmac.process(utf8.encode(message));

    final buffer = utf8.encode(magic) + pubkeyBuffer + utf8.encode(message) + checkSum;
    expect(() => Ecies().AESDecrypt(buffer, alicePrivKey), throwsException);


  });

  test('Can decrypt a message', (){
    final messageBuffer = utf8.encode('this is my test message');

    final cipherText1 = base64Decode('QklFMQOGFyMXLo9Qv047K3BYJhmnJgt58EC8skYP/R2QU/U0yXXHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbiaH4FsxKIOOvzolIFVAS0FplUmib2HnlAM1yP/iiPsU=');
    expect(Ecies().AESDecrypt(cipherText1, alicePrivKey), equals(messageBuffer));

    final cipherText2 = base64Decode('QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo=');
    expect(Ecies().AESDecrypt(cipherText2, bobPrivKey), equals(messageBuffer));

  });

  test('Can encrypt a message', (){

    final messageBuffer = utf8.encode('this is my test message');
    final aliceToBobCipherText = 'QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo=';
    final bobToAliceCipherText = 'QklFMQOGFyMXLo9Qv047K3BYJhmnJgt58EC8skYP/R2QU/U0yXXHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbiaH4FsxKIOOvzolIFVAS0FplUmib2HnlAM1yP/iiPsU=';

    expect(base64Encode(Ecies().AESEncrypt(messageBuffer,alicePrivKey, bobPrivKey.publicKey)), equals(aliceToBobCipherText));
    expect(base64Encode(Ecies().AESEncrypt(messageBuffer,bobPrivKey, alicePrivKey.publicKey)), equals(bobToAliceCipherText));

  });

}