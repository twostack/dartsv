# Introduction

## Overview

TwoStack WalletSDK is a Bitcoin library for the Dart Language \( [dartlang.org](https://dartlang.org) \), loosely based on the Moneybutton/BSV Javascript library. This library has been built in line with the ideals espoused by BitcoinSV, i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.

This library therefore lacks , and will not implement :
* Segregated Witness \(Segwit\) Transaction support
* Schnorr Signature support 
* Check Datasig \(OP\_CHECKDATASIG\) 

Current Supported features are :
* P2PKH Transactions \(building and spending from\)
* Data-only Transactions
* HD Key Derivation \(BIP32\)
* Original Bitcoin Address format 
* Bitcoin Signed Messages
* Bip39 Mnemonic Support (BIP39)
* A built-in Bitcoin Script Interpreter

Pending Features :
* P2SH support \(low priority since it will be deprecated in BitcoinSV\)

#### Sample of the Transaction API:

```dart
String createWalletTxn(Address address, List<TransactionInput> utxosToSpendFrom, BigInt amount ){

    var transaction = new Transaction()
        .spendFromInputs(utxosToSpendFrom)
        .spendTo(address, amount)
        .sendChangeTo(_receivingAddress) // spend change to myself
        .withFeePerKb(100000)
        .signWith(this._walletPrivKey, sighashType: SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID);

    return transaction.serialize();
}
```

### Installation

This library was built using version \(2.3.1\) of the Dart SDK [https://dart.dev/tools/sdk](https://dart.dev/tools/sdk), but should work with _Dart SDK 2.1.x_ onwards.  
Therefore, as a pre-requisite ensure that you have at least that version of the Dart SDK installed before proceeding.

Navigate to the root folder of this project, and pull the required supported Dart libraries using the `pub` package manager.

```text
> pub get
```

### Running the Tests

In the root folder of this project, run the command:

```text
> pub run test
```

## Acknowledgement

A debt of gratitude is owed to the developers acknowledged in the LICENSE file. Without the hard work of individuals working on earlier library and node implementations like Bitcoin Core, Bitcoin Cash, MoneyButton/BSV, BitcoinJ and many more, this library would likely not have come to fruition. Thank you.

## Contact

You can reach the author at :

* @beardpappa on Twitter
* beardpappa@moneybutton.com \(PayMail to buy me a beer\)
* stephan@werkswinkel.com

