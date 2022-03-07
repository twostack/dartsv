import 'dart:typed_data';
import 'dart:convert';
import 'utils.dart';
import 'package:collection/collection.dart';
import '../exceptions.dart';

/*
    Ported from bitcoinj-sv 0.1.1
    by Stephan February
    7 April 2019
 */

var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

List<int> decode(String input) {
  if (input.isEmpty) {
    return <int>[];
  }

  var encodedInput = utf8.encode(input);
  var uintAlphabet = utf8.encode(ALPHABET);

  List<int?> INDEXES = List<int>.filled(128, -1);
  for (int i = 0; i < ALPHABET.length; i++) {
      INDEXES[uintAlphabet[i]] = i;
  }

  // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
  List<int> input58 = List<int>.filled(encodedInput.length, 0);
  for (int i = 0; i < encodedInput.length; ++i) {
    var c = encodedInput[i];
    var digit = c < 128 ? INDEXES[c]! : -1;
    if (digit < 0) {
      var buff = <int>[c];
      var invalidChar = utf8.decode(buff);
      throw new AddressFormatException(
          "Illegal character " + invalidChar + " at position " + i.toString());
    }
    input58[i] = digit;
  }

  // Count leading zeros.
  int zeros = 0;
  while (zeros < input58.length && input58[zeros] == 0) {
    ++zeros;
  }

  // Convert base-58 digits to base-256 digits.
  var decoded = List<int>.filled(encodedInput.length, 0);
  int outputStart = decoded.length;
  for (int inputStart = zeros; inputStart < input58.length;) {
    decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
    if (input58[inputStart] == 0) {
      ++inputStart; // optimization - skip leading zeros
    }
  }

  // Ignore extra leading zeroes that were added during the calculation.
  while (outputStart < decoded.length && decoded[outputStart] == 0) {
    ++outputStart;
  }

  // Return decoded data (including original number of leading zeros).
  return decoded.sublist(outputStart - zeros, decoded.length);
}

/**
 * Divides a number, represented as an array of bytes each containing a single digit
 * in the specified base, by the given divisor. The given number is modified in-place
 * to contain the quotient, and the return value is the remainder.
 */
divmod(List<int> number, int firstDigit, int base, int divisor) {
// this is just long division which accounts for the base of the input digits
  int remainder = 0;
  for (int i = firstDigit; i < number.length; i++) {
    int digit = number[i] & 0xFF;
    int temp = remainder * base + digit;
    number[i] = (temp / divisor).toInt();
    remainder = temp % divisor;
  }

  return remainder.toSigned(8);
}


/**
 * Encodes the given bytes as a base58 string (no checksum is appended).
 */
Uint8List encode(List<int> encodedInput){
    var uintAlphabet = utf8.encode(ALPHABET);
    var ENCODED_ZERO = uintAlphabet[0];

//    var encodedInput = utf8.encode(input);

    if (encodedInput.isEmpty) {
        return <int>[] as Uint8List;
    }

    // Count leading zeros.
    int zeros = 0;
    while (zeros < encodedInput.length && encodedInput[zeros] == 0) {
        ++zeros;
    }

    // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
    //input = Arrays.copyOf(input, input.length); // since we modify it in-place
    Uint8List encoded = Uint8List(encodedInput.length * 2); // upper bound <----- ???
    int outputStart = encoded.length;
    for (int inputStart = zeros; inputStart < encodedInput.length; ) {
        encoded[--outputStart] = uintAlphabet[divmod(encodedInput, inputStart, 256, 58)];
        if (encodedInput[inputStart] == 0) {
            ++inputStart; // optimization - skip leading zeros
        }
    }
    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
        ++outputStart;
    }
    while (--zeros >= 0) {
        encoded[--outputStart] = ENCODED_ZERO;
    }
    // Return encoded string (including encoded leading zeros).
    return encoded.sublist(outputStart, encoded.length );
}

List<int> decodeChecked(String input) {

    List<int> decoded  = decode(input);
    if (decoded.length < 4)
        throw new AddressFormatException("Input too short");
    

    List<int> data = decoded.sublist(0, decoded.length - 4);
    List<int> checksum = decoded.sublist(decoded.length - 4, decoded.length);
    List<int> actualChecksum = sha256Twice(data).sublist(0, 4);

    var byteConverted = actualChecksum.map((elem) => elem.toSigned(8)); //convert unsigned list back to signed
    if ( !IterableEquality().equals(checksum ,byteConverted) )
        throw new BadChecksumException("Checksum does not validate");

    return data;
}

