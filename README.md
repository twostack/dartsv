# Introduction

![Dart CI](https://github.com/twostack/dartsv/workflows/Dart%20CI/badge.svg)

## Overview

TwoStack WalletSDK is a Bitcoin library for the Dart Language \( [dartlang.org](https://dartlang.org) \), loosely based on the [Moneybutton/BSV](https://github.com/moneybutton/bsv) Javascript library. This library has been built in line with the ideals espoused by BitcoinSV, i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.


This library therefore lacks , and will not implement :
* Segregated Witness \(Segwit\) Transaction support
* Schnorr Signature support 
* Check Datasig \(OP\_CHECKDATASIG\) 

Current Supported features are :
* P2PKH Transactions 
* P2SH Transactions 
* P2MS Transactions (naked multisig)
* P2PK Transactions
* Custom-Script Builder Interface to support novel locking/spending conditions within Script
* Data-only Transactions
* HD Key Derivation \(BIP32\)
* Original Bitcoin Address format 
* Bitcoin Signed Messages
* Mnemonic Seed Support (BIP39)
* A built-in Bitcoin Script Interpreter
* ECIES Encryption / Decryption (Supports Electrum ECIES / BIE1 )

#### Sample of the Transaction API:

```dart
  var unlockBuilder = P2PKHUnlockBuilder(privateKey.publicKey);
  var transaction = new Transaction()
      .spendFromOutput(utxo, Transaction.NLOCKTIME_MAX_VALUE, scriptBuilder: unlockBuilder) 
      .spendTo(recipientAddress, BigInt.from(50000000), scriptBuilder: P2PKHLockBuilder(recipientAddress)) 
      .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress)) 
      .withFeePerKb(1000); 

  //Sign the Transaction Input
  transaction.signInput(0, privateKey, sighashType: SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID);

```

### Installation
**Note**: Version 1.0.0 is a major version update to support Dart Null-Safety.

This library was built using version _2.14.3_ of the Dart SDK( [https://dart.dev/tools/sdk](https://dart.dev/tools/sdk) ).  
As of Version 1.0.0 this library supports Dart Null Safety, and will therefore require a minimum SDK Version of 2.12.2.

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

* @twostack_org on Twitter
* beardpappa@moneybutton.com \(PayMail to buy me a beer\)
* stephan@twostack.org

