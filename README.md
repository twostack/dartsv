# Introduction

![Dart CI](https://github.com/twostack/dartsv/workflows/Dart%20CI/badge.svg)

## Overview

TwoStack WalletSDK is a Bitcoin library for the Dart Language \( [dartlang.org](https://dartlang.org) \), loosely based on the [Moneybutton/BSV](https://github.com/moneybutton/bsv) Javascript library. This library has been built in line with the ideals espoused by BitcoinSV, i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.
It is intended for use in building multi-platform applications using the Flutter framework, or server-side
bitcoin applications using frameworks like [Serverpod](https://serverpod.dev/)

### A note about Version 2.x (August 2023)
Version 2.x of the library is a major refactor and breaks backwards compatibility 
with several previous library APIs. 

* A new `TransactionBuilder` class for composing Transactions
* Removal of the old Builder interface which was directly attached to the `Transaction` class
* A complete re-implementation of the Script Interpreter
* The `Sighash` class now exposes the SigHash Pre-Image; useful when creating `OP_PUSH_TX` spending scripts. 
* A new `ScriptBuilder` class to make it easy to create custom locking/unlocking scripts.
* Merged contributed code to have better Flutter Web support.

Generally Supported features are :
* Custom-Script Builder Interface to support novel locking/spending conditions within Script
* Pre-built library code to support "standard" locking/unlocking scripts
    * P2PKH Transactions 
    * P2SH Transactions 
    * P2MS Transactions (naked multisig)
    * P2PK Transactions
    * Data-only Transactions (locked with `OP_FALSE OP_RETURN`)
    * Spendable data-carrier Transactions (locked with `PUSH_DATA [your_data] OP_DROP [P2PKH locking code]`)
* HD Key Derivation \(BIP32\)
* Original Bitcoin Address format 
* Bitcoin Signed Messages
* Mnemonic Seed Support (BIP39)
* A built-in Bitcoin Script Interpreter
* ECIES Encryption / Decryption (Supports Electrum ECIES / BIE1 )

#### Sample of the Transaction API:

```dart
    var utxo = txWithUTXO.outputs[0]; 
    var outpoint = TransactionOutpoint(txWithUTXO.id, 0, utxo.satoshis, utxo.script);
    var signer = TransactionSigner(SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value, privateKey);

    var unlocker = P2PKHUnlockBuilder(privateKey.publicKey);
    
    var transaction = TransactionBuilder()
        .spendFromOutpointWithSigner(signer, outpoint, TransactionInput.MAX_SEQ_NUMBER, unlocker)
        .spendToPKH(recipientAddress, BigInt.from(50000000)) //spend half of a bitcoin 
        .sendChangeToPKH(changeAddress) // spend change to a different address
        .withFeePerKb(50) //set a fee of 50 satoshis per kilobyte
        .build(false); //build the transaction, disabling checks

    //at this point you have a fully signed transaction ready to be broadcast

    try {
      transaction.verify(); //perform a pre-broadcast sanity check on the transaction
    } on VerificationException catch (ex){
      print("Transaction failed verification - ${ex.cause}");  
    }

```

### Installation

This library was built using version _3.0.7_ of the Dart SDK( [https://dart.dev/tools/sdk](https://dart.dev/tools/sdk) ).  
As of Version 1.0.0 this library supports Dart Null Safety. Current minimum Dart SDK version required is version _2.17.0_. 

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

A debt of gratitude is owed to the developers acknowledged in the LICENSE file. 
Without the hard work of individuals working on earlier library and node 
implementations like Bitcoin Core, Bitcoin Cash, MoneyButton/BSV, BitcoinJ and many 
more, this library would likely not have come to fruition. Thank you.

## Contact

You can reach the author at :

* @twostack_org on Twitter
* beardpappa@handcash.io \(PayMail to buy me a beer\)
* stephan@twostack.org (drop me an email. GPG supported. )

