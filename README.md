##### THIS IS A ALPHA RELEASE. PROCEED WITH MAXIMUM CAUTION.

### Overview

DartSV is a Bitcoin library for the Dart Language ( [dartlang.org](https://dartlang.org) ), loosely based on the Moneybutton/BSV Javascript library. 
This library has been built in line with the ideals espoused by BitcoinSV, i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.  

This library therefore lacks , and will not implement :  
* Segregated Witness (Segwit) Transaction support
* Schnorr Signature support 
* Check Datasig (OP_CHECKDATASIG) 

Current Supported features are : 
* P2PKH Transactions
* Data-only Transactions (untested)
* HD Key Derivation (BIP32)
* Original Bitcoin Address format 

Pending Features : 
* Script Interpreter (high priority)
* P2SH support (low priority since it will be deprecated in BitcoinSV)
* Broader support for original OP_CODES as they become available on BitcoinSV mainnet 

### Note to Developers
This is an Alpha-Release aimed at interested individuals and experienced developers for the purpose of getting feedback on library improvements as I build towards a stable 0.1.0 release. 
I am especially interested in hearing from Flutter developers. 

Documentation is lacking. Your best source for seeing how the library works is the `cli-example` application on GitHub: [DartSV CLI Example](https://github.com/twostack/cli-example)

Here is a small sample of the Transaction API (method taken from `cli-example`): 
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

#### Installation 
This library was built using the latest version (2.3.1) of the Dart SDK [https://dart.dev/tools/sdk](https://dart.dev/tools/sdk), but should work with *Dart SDK 2.1.x* onwards.  
Therefore, as a pre-requisite ensure that you have at least that version of the Dart SDK installed before proceeding.  

Navigate to the root folder of this project, and pull the required supported Dart libraries using the `pub` package manager. 
```
> pub get 
```

#### Running the Tests
In the root folder of this project, run the shell script : 
```
> ./runtests.sh
```

### Acknowledgement
A debt of gratitude is owed to the developers acknowledged in the LICENSE file. Without the hard work of individuals working on earlier library and node implementations like Bitcoin Core, Bitcoin Cash, MoneyButton/BSV, BitcoinJ and many more, this library would likely not have come to fruition. Thank you. 


