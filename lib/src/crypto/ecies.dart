import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';

/// A Class for performing Elliptic Curve Integrated Encryption Scheme operations.
///
/// This class only makes provision for the "Electrum ECIES" aka "BIE1" serialization
/// format for the cipherText.
class Ecies {
  // final ECDomainParameters _domainParams =  ECDomainParameters('secp256k1');
  final SHA256Digest _sha256Digest = SHA256Digest();
  final tagLength = 32; //size of hmac

  /// Perform an ECIES encryption using AES for the symmetric cipher.
  ///
  /// [messageBuffer] - The buffer to encrypt. Note that the buffer in this instance has a very specific
  /// encoding format called "BIE1" or "Electrum ECIES". It is in essence a serialization format with a
  /// built-in checksum.
  ///   - bytes [0 - 4] : Magic value. Literally "BIE1".
  ///   - bytes [4 - 37] : Compressed Public Key
  ///   - bytes [37 - (length - 32) ] : Actual cipherText
  ///   - bytes [ length - 32 ] : (last 32 bytes) Checksum value
  ///
  /// [senderPrivateKey] - Private Key of the sending party
  ///
  /// [recipientPublicKey] - Public Key of the party who can decrypt the message
  ///
  List<int> AESEncrypt(List<int> messageBuffer, SVPrivateKey senderPrivateKey, SVPublicKey recipientPublicKey){

    //Encryption requires derivation of a cipher using the other party's Public Key
    // Bob is sender, Alice is recipient of encrypted message
    // Qb = k o Qa, where
    //     Qb = Bob's Public Key;
    //     k = Bob's private key;
    //     Qa = Alice's public key;

    final ECPoint S = (recipientPublicKey.point * senderPrivateKey.privateKey)!; //point multiplication
    final pubkeyS = SVPublicKey.fromXY(S.x!.toBigInteger()!, S.y!.toBigInteger()!);
    final pubkeyBuffer = HEX.decode(pubkeyS.getEncoded(true));
    final pubkeyHash = SHA512Digest().process(pubkeyBuffer as Uint8List);

    //initialization vector parameters
    final iv = pubkeyHash.sublist(0, 16);
    final kE = pubkeyHash.sublist(16, 32);
    final kM = pubkeyHash.sublist(32, 64);

    CipherParameters params = PaddedBlockCipherParameters(ParametersWithIV(KeyParameter(kE), iv), null);
    BlockCipher encryptionCipher = PaddedBlockCipher('AES/CBC/PKCS7');
    encryptionCipher.init(true, params);

    final cipherText = encryptionCipher.process(messageBuffer as Uint8List);
    final magic = utf8.encode('BIE1');

    final encodedBuffer = Uint8List.fromList(magic + HEX.decode(senderPrivateKey.publicKey.toHex()) + cipherText);

    //calc checksum
    final hmac = _calculateHmac(kM, encodedBuffer);

    return encodedBuffer + hmac;
  }

  Uint8List _calculateHmac(Uint8List kM, Uint8List encodedBuffer) {
    final sha256Hmac = HMac(_sha256Digest, 64);
    sha256Hmac.init(KeyParameter(kM));
    final calculatedChecksum = sha256Hmac.process(encodedBuffer);
    return calculatedChecksum;
  }

  /*
   */

  /// Perform an ECIES decryption using AES for the symmetric cipher.
  ///
  /// [cipherText] -  The buffer to decrypt. Note that the buffer in this instance has a very specific
  /// encoding format called "BIE1" or "Electrum ECIES". It is in essence a serialization format with a
  /// built-in checksum.
  ///   - bytes [0 - 4] : Magic value. Literally "BIE1".
  ///   - bytes [4 - 37] : Compressed Public Key
  ///   - bytes [37 - (length - 32) ] : Actual cipherText
  ///   - bytes [ length - 32 ] : (last 32 bytes) Checksum valu
  ///
  /// [recipientPrivateKey] - Private Key of the receiving party
  ///
  List<int> AESDecrypt(List<int> cipherText, SVPrivateKey recipientPrivateKey){

    //AES Cipher is calculated as
    //1) S = recipientPrivateKey o senderPublicKey
    //2) cipher = S.x

    if (cipherText.length < 37){
      throw Exception('Buffer is too small ');
    }

    final magic = utf8.decode(cipherText.sublist(0, 4));

    if ( magic != 'BIE1'){
      throw Exception('Not a BIE1-encoded buffer');
    }

    final senderPubkeyBuffer = cipherText.sublist(4, 37);
    final senderPublicKey = SVPublicKey.fromHex(HEX.encode(senderPubkeyBuffer));

    //calculate S = recipientPrivateKey o senderPublicKey
    final S = (senderPublicKey.point * recipientPrivateKey.privateKey)!; //point multiplication
    // final cipher = S.x;

    if (cipherText.length - tagLength <= 37 ){
      throw Exception('Invalid Checksum detected. Combined sum of Checksum and Message makes no sense');
    }

    //validate the checksum bytes
    final pubkeyS = SVPublicKey.fromXY(S.x!.toBigInteger()!, S.y!.toBigInteger()!);
    final pubkeyBuffer = HEX.decode(pubkeyS.getEncoded(true));
    final pubkeyHash = SHA512Digest().process(pubkeyBuffer as Uint8List);

    //initialization vector parameters
    final iv = pubkeyHash.sublist(0, 16);
    final kE = pubkeyHash.sublist(16, 32);
    final kM = pubkeyHash.sublist(32, 64);
    final message = Uint8List.fromList(cipherText.sublist(0, cipherText.length - tagLength));

    final hmac = _calculateHmac(kM, message);
    final messageChecksum = cipherText.sublist(cipherText.length - tagLength, cipherText.length);

    if (!ListEquality().equals(messageChecksum, hmac)){
      throw Exception('HMAC checksum failed to validate');
    }

    //decrypt!
    CipherParameters params = PaddedBlockCipherParameters(ParametersWithIV(KeyParameter(kE), iv), null);
    BlockCipher decryptionCipher = PaddedBlockCipher("AES/CBC/PKCS7");
    decryptionCipher.init(false, params);

    final decrypted = decryptionCipher.process(cipherText.sublist(37, cipherText.length - tagLength) as Uint8List);
    return decrypted;
  }
}