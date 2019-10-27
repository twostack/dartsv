
import 'dart:convert';

import 'package:dartsv/src/bip39/bip39.dart';
import 'package:resource/resource.dart';
import 'package:test/test.dart';

main(){

    String getWordlistName(Wordlist wordlist) {
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

    Future<List<String>> loadWordlist(Wordlist wordlist) async {
            final res = Resource('package:dartsv/src/bip39/wordlists/${getWordlistName(wordlist)}.txt');
            final rawWords = await res.readAsString(encoding: utf8);
            final result = rawWords
                .split('\n')
                .map((s) => s.trim())
                .where((s) => s.isNotEmpty)
                .toList(growable: false);
            return result;
    }

    List<String> ENGLISH_WORDS;
    List<String> SPANISH_WORDS;

    setUp(() async {

        ENGLISH_WORDS = await loadWordlist(Wordlist.ENGLISH);
        SPANISH_WORDS = await loadWordlist(Wordlist.SPANISH);
    });

    test('it should make a new mnemonic', () async {

        var mnemonic = await new Mnemonic().generateMnemonic();
        var mnemonic2 = await new Mnemonic().generateMnemonic();

        expect(mnemonic == mnemonic2, isFalse);
        expect(ENGLISH_WORDS.contains(mnemonic.split(' ')[0]), isTrue);
        expect(ENGLISH_WORDS.contains(mnemonic.split(' ')[1]), isTrue);
        expect(ENGLISH_WORDS.contains(mnemonic.split(' ')[2]), isTrue);

        var mnemonic3 = await new Mnemonic(DEFAULT_WORDLIST: Wordlist.SPANISH).generateMnemonic();

        expect(SPANISH_WORDS.contains(mnemonic3.split(' ')[0]), isTrue);
        expect(SPANISH_WORDS.contains(mnemonic3.split(' ')[1]), isTrue);
        expect(SPANISH_WORDS.contains(mnemonic3.split(' ')[2]), isTrue);

    });

    test('english wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.ENGLISH);

        expect(wordList.length, equals(2048));
    });

    test('spanish wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.SPANISH);

        expect(wordList.length, equals(2048));
    });

    test('japanese wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.JAPANESE);

        expect(wordList.length, equals(2048));
    });


    test('simplified chinese wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.CHINESE_SIMPLIFIED);

        expect(wordList.length, equals(2048));
    });

    test('traditional chinese wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.CHINESE_TRADITIONAL);

        expect(wordList.length, equals(2048));
    });

    test('french wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.FRENCH);

        expect(wordList.length, equals(2048));
    });


    test('italian wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.ITALIAN);

        expect(wordList.length, equals(2048));
    });

    test('korean wordlist is complete', () async {
        var wordList = await new Mnemonic().getWordList(Wordlist.KOREAN);

        expect(wordList.length, equals(2048));
    });
}

