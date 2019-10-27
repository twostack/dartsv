import 'dart:typed_data';
import 'dart:math';
import 'dart:convert';
import 'dart:async';

import 'package:hex/hex.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:resource/resource.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:unorm_dart/unorm_dart.dart';
import 'package:pointycastle/api.dart';

//thanks to https://github.com/yshrsmz/bip39-dart
//the source code come from here


enum Wordlist {
  CHINESE_SIMPLIFIED,
  CHINESE_TRADITIONAL,
  ENGLISH,
  FRENCH,
  ITALIAN,
  JAPANESE,
  KOREAN,
  SPANISH,
}

typedef Uint8List RandomBytes(int size);

class Mnemonic {

  final _wordlistCache = Map<Wordlist, List<dynamic>>();

  Wordlist DEFAULT_WORDLIST;

  static const int _SIZE_8BITS = 255;
  static const String _INVALID_ENTROPY = 'Invalid entroy';
  static const String _INVALID_MNEMONIC = 'Invalid mnemonic';
  static const String _INVALID_CHECKSUM = 'Invalid checksum';

  List<String> _wordRes ;


  Mnemonic({this.DEFAULT_WORDLIST = Wordlist.ENGLISH});


  static Uint8List _nextBytes(int size) {
    final rnd = Random.secure();
    final bytes = Uint8List(size);
    for (var i = 0; i < size; i++) {
      bytes[i] = rnd.nextInt(_SIZE_8BITS);
    }
    return bytes;
  }

  /// Generates a random mnemonic.
  ///
  /// Defaults to 128-bits of entropy.
  /// By default it uses [Random.secure()] under the food to get random bytes,
  /// but you can swap RNG by providing [randomBytes].
  /// Default wordlist is English, but you can use different wordlist by providing [wordlist].
  Future<String> generateMnemonic({ int strength = 128, RandomBytes randomBytes = _nextBytes }) async {

    assert(strength % 32 == 0);

    final entropy = randomBytes(strength ~/ 8);

    return await entropyToMnemonic(entropy);
  }

  /// Converts HEX string [entropy] to mnemonic code
  Future<String> entropyHexToMnemonic(String entropy) {
    return entropyToMnemonic(HEX.decode(entropy));
  }

  /// Converts [entropy] to mnemonic code.
  Future<String> entropyToMnemonic(Uint8List entropy) async {

    if (entropy.length < 16) {
      throw ArgumentError(_INVALID_ENTROPY);
    }
    if (entropy.length > 32) {
      throw ArgumentError(_INVALID_ENTROPY);
    }
    if (entropy.length % 4 != 0) {
      throw ArgumentError(_INVALID_ENTROPY);
    }

    final entroypyBits = _bytesToBinary(entropy);
    final checksumBits = _deriveChecksumBits(entropy);

    final bits = entroypyBits + checksumBits;

    final regex = new RegExp(r".{1,11}", caseSensitive: false, multiLine: false);
    final chunks = regex
        .allMatches(bits)
        .map((match) => match.group(0))
        .toList(growable: false);

    this._wordRes = await _loadWordlist(DEFAULT_WORDLIST);

    return chunks
        .map((binary) => this._wordRes[_binaryToByte(binary)])
        .join(DEFAULT_WORDLIST == Wordlist.JAPANESE ? '\u3000' : ' ');
  }

  String _deriveChecksumBits(Uint8List entropy) {
    final ENT = entropy.length * 8;
    final CS = ENT ~/ 32;

    //final hash = sha256.newInstance().convert(entropy);
    var hash = sha256(entropy);
    return _bytesToBinary(Uint8List.fromList(hash)).substring(0, CS);
  }


  String _bytesToBinary(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(2).padLeft(8, '0')).join('');
  }

  int _binaryToByte(String binary) {
    return int.parse(binary, radix: 2);
  }


  Future<List<String>> _loadWordlist(Wordlist wordlist) async {
    if (_wordlistCache.containsKey(wordlist)) {
      return _wordlistCache[wordlist];
    } else {
      final res = Resource(
          'package:dartsv/src/bip39/wordlists/${_getWordlistName(wordlist)}.txt');
      final rawWords = await res.readAsString(encoding: utf8);
      final result = rawWords
          .split('\n')
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList(growable: false);
      _wordlistCache[wordlist] = result;
      return result;
    }
  }

  String _getWordlistName(Wordlist wordlist) {
    switch (wordlist) {
      case Wordlist.CHINESE_SIMPLIFIED:
        return 'chinese_simplified';
      case Wordlist.CHINESE_TRADITIONAL:
        return 'chinese_traditional';
      case Wordlist.ENGLISH:
        return 'english';
      case Wordlist.FRENCH:
        return 'french';
      case Wordlist.ITALIAN:
        return 'italian';
      case Wordlist.JAPANESE:
        return 'japanese';
      case Wordlist.KOREAN:
        return 'korean';
      case Wordlist.SPANISH:
        return 'spanish';
      default:
        return 'english';
    }
  }

  String _salt(String password) {
    return 'mnemonic${password ?? ""}';
  }

  /// Converts [mnemonic] code to seed.
  ///
  /// Returns Uint8List.
  Uint8List toSeed(String mnemonic, [String password = ""]) {
    final mnemonicBuffer = utf8.encode(nfkd(mnemonic));
    final saltBuffer = utf8.encode(_salt(nfkd(password)));
    final pbkdf2 = KeyDerivator('SHA-512/HMAC/PBKDF2');

    pbkdf2.init(Pbkdf2Parameters(saltBuffer, 2048, 64));
    return pbkdf2.process(mnemonicBuffer);
  }


  /// Converts [mnemonic] code to seed, as hex string.
  ///
  /// Returns hex string.
  String toSeedHex(String mnemonic, [String password = ""]) {
    return toSeed(mnemonic, password).map((byte) {
      return byte.toRadixString(16).padLeft(2, '0');
    }).join('');
  }

  /// Converts [mnemonic] code to entropy.
  Future<Uint8List> mnemonicToEntropy(String mnemonic) async {
    this._wordRes = await _loadWordlist(DEFAULT_WORDLIST);
    final words = nfkd(mnemonic).split(' ');

    if (words.length % 3 != 0) {
      throw new ArgumentError(_INVALID_MNEMONIC);
    }

    // convert word indices to 11bit binary strings
    final bits = words.map((word) {
      final index = this._wordRes.indexOf(word);
      if (index == -1) {
        throw ArgumentError(_INVALID_MNEMONIC);
      }

      return index.toRadixString(2).padLeft(11, '0');
    }).join('');

    // split the binary string into ENT/CS
    final dividerIndex = (bits.length / 33).floor() * 32;
    final entropyBits = bits.substring(0, dividerIndex);
    final checksumBits = bits.substring(dividerIndex);

    final regex = RegExp(r".{1,8}");

    final entropyBytes = Uint8List.fromList(regex
        .allMatches(entropyBits)
        .map((match) => _binaryToByte(match.group(0)))
        .toList(growable: false));
    if (entropyBytes.length < 16) {
      throw StateError(_INVALID_ENTROPY);
    }
    if (entropyBytes.length > 32) {
      throw StateError(_INVALID_ENTROPY);
    }
    if (entropyBytes.length % 4 != 0) {
      throw StateError(_INVALID_ENTROPY);
    }

    final newCheckSum = _deriveChecksumBits(entropyBytes);
    if (newCheckSum != checksumBits) {
      throw StateError(_INVALID_CHECKSUM);
    }

    return entropyBytes;
  }

  /// Check if [mnemonic] code is valid.
  Future<bool> validateMnemonic(String mnemonic) async {
    try {
      await mnemonicToEntropy(mnemonic);
    } catch (e) {
      return false;
    }
    return true;
  }

  Future<List<String>> getWordList(Wordlist wordList) async {
    return _loadWordlist(wordList);
  }

}


//void main() async{
// var mnemoic = await generateMnemonic();
// var seed = mnemonicToSeedHex('cheese coconut blur slam train brother rent lawn ten silk crystal transfer');
//
// print(seed);
//
//  print(mnemoic);
//
//  print(mnemonicToSeedHex(mnemoic));
//
//}

