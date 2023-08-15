import 'dart:math';

import 'package:dartsv/src/transaction/preconditions.dart';
import 'package:decimal/decimal.dart';

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
class Coin {

  /**
   * The number of satoshis of this monetary value.
   */
  BigInt _satoshis;

  Coin(this._satoshis);

  /**
   * Number of decimals for one Bitcoin. This constant is useful for quick adapting to other coins because a lot of
   * constants derive from it.
   */
  static final int SMALLEST_UNIT_EXPONENT = 8;


  /**
   * The number of satoshis equal to one bitcoin.
   */
  static final BigInt COIN_VALUE = BigInt.from(pow(10, SMALLEST_UNIT_EXPONENT));

  /**
   * Zero Bitcoins.
   */
  static final Coin ZERO = valueOf(BigInt.zero);

  /**
   * One Bitcoin.
   */
  static final Coin COIN = Coin.valueOf(COIN_VALUE);

  /**
   * 0.01 Bitcoins. This unit is not really used much.
   */
  static final Coin CENT = COIN.divide(100);

  /**
   * 0.001 Bitcoins, also known as 1 mBTC.
   */
  static final Coin MILLICOIN = COIN.divide(1000);

  /**
   * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
   */
  static final Coin MICROCOIN = MILLICOIN.divide(1000);

  /**
   * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
   */
  static final Coin SATOSHI = Coin.valueOf(BigInt.one);

  static final Coin FIFTY_COINS = COIN.multiply(50);

  /**
   * Represents a monetary value of minus one satoshi.
   */
  static final Coin NEGATIVE_SATOSHI = Coin.valueOf(-1);


  static Coin valueOf(final BigInt satoshis) {
    return Coin(satoshis);
  }


  int smallestUnitExponent() {
    return SMALLEST_UNIT_EXPONENT;
  }

  /**
   * Returns the number of satoshis of this monetary value.
   */

  BigInt getValue() {
    return this._satoshis;
  }

  /**
   * Convert an amount expressed in the way humans are used to into satoshis.
   */
  // static Coin valueOf(final int coins, final int cents) {
  //   Preconditions.assertTrue(cents < 100);
  //   Preconditions.assertTrue(cents >= 0);
  //   Preconditions.assertTrue(coins >= 0);
  //   final Coin coin = COIN.multiply(coins).add(CENT.multiply(cents));
  //   return coin;
  // }

  /**<p>
   * Parses an amount expressed in the way humans are used to.
   * </p>
   * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
   * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
   *
   * @throws IllegalArgumentException if you try to specify fractional satoshis, or a value out of range.
   */
  static Coin parseCoin(final String str) {
    try {
      BigInt satoshis = Decimal.parse(str)
          .shift(SMALLEST_UNIT_EXPONENT)
          .toBigInt();
      return Coin.valueOf(satoshis);
    } on FormatException catch (e) {
      throw ArgumentError(e); // Repackage exception to honor method contract
    }
  }

  /**
   * Convert a decimal amount of BTC into satoshis.
   *
   * @param coins number of coins
   * @return number of satoshis
   */
  static BigInt btcToSatoshi(Decimal coins) {
    return coins.shift(SMALLEST_UNIT_EXPONENT).toBigInt();
  }

  /**
   * Convert an amount in satoshis to an amount in BTC.
   *
   * @param satoshis number of satoshis
   * @return number of bitcoins (in BTC)
   */
  static Decimal satoshiToBtc(BigInt satoshis) {
    return new Decimal.fromBigInt(satoshis).shift(SMALLEST_UNIT_EXPONENT);
  }

  /**
   * Create a {@code Coin} from a decimal amount of BTC.
   *
   * @param coins number of coins (in BTC)
   * @return {@code Coin} object containing value in satoshis
   */
  static Coin ofBtc(Decimal coins) {
    return Coin.valueOf(btcToSatoshi(coins));
  }

  /**
   * Create a {@code Coin} from a int integer number of satoshis.
   *
   * @param satoshis number of satoshis
   * @return {@code Coin} object containing value in satoshis
   */
  static Coin ofSat(BigInt satoshis) {
    return Coin.valueOf(satoshis);
  }


  /**
   * Convert to number of bitcoin (in BTC)
   *
   * @return decimal number of bitcoin (in BTC)
   */
  Decimal toBtc() {
    return satoshiToBtc(this._satoshis);
  }

  /**
   * Create a {@code Coin} by parsing a {@code String} amount expressed in "the way humans are used to".
   * The amount is cut to satoshi precision.
   *
   * @param str string in a format understood by {@link BigDecimal#BigDecimal(String)}, for example "0", "1", "0.10",
   *      * "1.23E3", "1234.5E-5".
   * @return {@code Coin} object containing value in satoshis
   * @throws IllegalArgumentException
   *             if you try to specify a value out of range.
   */
  static Coin parseCoinInexact(final String str) {
    try {
      BigInt satoshis = Decimal.parse(str)
          .shift(SMALLEST_UNIT_EXPONENT)
          .toBigInt();
      return Coin.valueOf(satoshis);
    } on FormatException catch (e) {
      throw new ArgumentError(e); // Repackage exception to honor method contract
    }
  }

  Coin add(final Coin value) {
    return Coin(LongMath.checkedAdd(this._satoshis, value.getValue()));
  }

  /** Alias for add */
  Coin plus(Coin value) {
    return add(value);
  }

  Coin subtract(final Coin value) {
    return new Coin(LongMath.checkedSubtract(this._satoshis, value.getValue()));
  }

  /** Alias for subtract */
  Coin minus(final Coin value) {
    return subtract(value);
  }

  Coin multiply(final int factor) {
    return new Coin(LongMath.checkedMultiply(this._satoshis, factor));
  }

  /** Alias for multiply */
  Coin times(final int factor) {
    return multiply(factor);
  }

  /** Alias for multiply */
  // Coin times(final int factor) {
  //   return multiply(factor);
  // }

  Coin divide(final BigInt divisor) {
    return Coin(this._satoshis ~/ divisor);
  }

  /** Alias for divide */
  Coin div(final BigInt divisor) {
    return divide(divisor);
  }

  List<Coin> divideAndRemainder(final BigInt divisor) {
    return [ divide(divisor) , Coin(this._satoshis % divisor) ];
  }

  // int divide(final Coin divisor) {
  //   return this.value / divisor.value;
  // }

  /**
   * Returns true if and only if this instance represents a monetary value greater than zero,
   * otherwise false.
   */
  bool isPositive() {
    return !_satoshis.isNegative;
  }

  /**
   * Returns true if and only if this instance represents a monetary value less than zero,
   * otherwise false.
   */
  bool isNegative() {
    return _satoshis.isNegative;
  }

  /**
   * Returns true if and only if this instance represents zero monetary value,
   * otherwise false.
   */
  bool isZero() {
    return _satoshis == BigInt.zero;
  }

  /**
   * Returns true if the monetary value represented by this instance is greater than that
   * of the given other Coin, otherwise false.
   */
  bool isGreaterThan(Coin other) {
    return compareTo(other) > 0;
  }

  /**
   * Returns true if the monetary value represented by this instance is less than that
   * of the given other Coin, otherwise false.
   */
  bool isLessThan(Coin other) {
    return compareTo(other) < 0;
  }

  Coin shiftLeft(final int n) {
    return Coin(this._satoshis << n);
  }

  Coin shiftRight(final int n) {
    return new Coin(this._satoshis >> n);
  }


  Coin negate() {
    return new Coin(-this._satoshis);
  }

  /**
   * Returns the number of satoshis of this monetary value. It's deprecated in favour of accessing {@link #value}
   * directly.
   */
  int longValue() {
    return this._satoshis.toInt();
  }

  // static final MonetaryFormat FRIENDLY_FORMAT = MonetaryFormat
  //     .BTC
  //     .minDecimals(2)
  //     .repeatOptionalDecimals(1, 6)
  //     .postfixCode();

  /**
   * Returns the value as a 0.12 type string. More digits after the decimal place will be used
   * if necessary, but two will always be present.
   */
  // String toFriendlyString() {
  //   return FRIENDLY_FORMAT.format(this).toString();
  // }
  //
  // static final MonetaryFormat PLAIN_FORMAT = MonetaryFormat.BTC.minDecimals(0)
  //     .repeatOptionalDecimals(1, 8)
  //     .noCode();

  /**
   * <p>
   * Returns the value as a plain string denominated in BTC.
   * The result is unformatted with no trailing zeroes.
   * For instance, a value of 150000 satoshis gives an output string of "0.0015" BTC
   * </p>
   */
  // String toPlainString() {
  //   return PLAIN_FORMAT.format(this).toString();
  // }


  String toString() {
    return this._satoshis.toString();
  }

  int compareTo(final Coin other) {
    return this._satoshis.compareTo(other.getValue());
  }
}