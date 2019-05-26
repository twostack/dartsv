
import 'dart:core';

import '../exceptions.dart';
import 'package:sprintf/sprintf.dart';

/*
Ported from BitcoinJ-SV
 */
class ChildNumber implements Comparable<ChildNumber> {
    /**
     * The bit that's set in the child number to indicate whether this key is "hardened". Given a hardened key, it is
     * not possible to derive a child public key if you know only the hardened public key. With a non-hardened key this
     * is possible, so you can derive trees of public keys given only a public parent, but the downside is that it's
     * possible to leak private keys if you disclose a parent public key and a child private key (elliptic curve maths
     * allows you to work upwards).
     */
    static final int HARDENED_BIT = 0x80000000;

    static final ChildNumber ZERO = new ChildNumber.fromIndex(0);
    static final ChildNumber ONE = new ChildNumber.fromIndex(1);
    static final ChildNumber ZERO_HARDENED = new ChildNumber(0, true);

    /** Integer i as per BIP 32 spec, including the MSB denoting derivation type (0 = public, 1 = private) **/
    int _i = 0;

    ChildNumber(int childNumber, bool isHardened) {
        if (_hasHardenedBit(childNumber))
            throw new IllegalArgumentException("Most significant bit is reserved and shouldn't be set: " + childNumber.toString());
        this._i = isHardened ? (childNumber | HARDENED_BIT) : childNumber;
    }

    ChildNumber.fromIndex(int i) {
        this._i = i;
    }

    /** Returns the uint32 encoded form of the path element, including the most significant bit. */
    int get i {
        return this._i;
    }

    bool isHardened() {
        return _hasHardenedBit(this._i);
    }

    static bool _hasHardenedBit(int a) {
        return (a & HARDENED_BIT) != 0;
    }

    /** Returns the child number without the hardening bit set (i.e. index in that part of the tree). */
    int num() {
        return this._i & (~HARDENED_BIT);
    }

    String toString() {
        return sprintf( "%d%s", [num(), isHardened() ? "H" : ""]);
    }


    bool operator ==(otherChild){

        if (otherChild == null || runtimeType != otherChild.runtimeType)
            return false;

        return this._i == otherChild.i;
    }

    get hashCode {
        return this._i;
    }

    int compareTo(ChildNumber other) {
        return this.num().compareTo(other.num());
    }
}
