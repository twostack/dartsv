## 2.1.0
 Bugfix : xpriv network byte decoding
 Bugfix : Script Interpreter fixes. Some of the OP_CODES were not properly processed 

 New Feature: Dedicated PreImage generator for working with OP_PUSH_TX-style covenants.

 Change: The Transaction Builder utility class now places the change output as the first 
 output by default. 

## 2.0.2
Bugfix: Bigint amount incorrectly encoded during sighash

- Fixes a bug in the buffer conversion to a bigintLE during sighash preimage calculation

## 2.0.1
Bugfix: Uint64 error when using with Flutter Web

- Dart2JS does not handle Uint64. Remove all references to readUint64 
  and writeUint64 for handling big numbers. 

## 2.0.0  
- Removed uncessary FFI dependency

- Hardened path verification / validation
  - Added addtional regex check to the path validation string
  - Exposed ChildNumber class in the API

- Tightened up the fee calculations
  - Removed the hard requirement of a change output during txn validation
  - Removed the hard lower limit of 256 sats per transaction as a fee basis
  
- fixed decimal display of coins

- Solve/work-around for issue-54
  - Problem: When importing the lib into flutter and attempting to
    generate mnemonics, it fails with "Unsupported operation: Isolate.resolvePackageUri"
    FIX: Allow passing a function to the library to help resolve resources using
    Flutter AssetBundle APIs .

- Refactoring tests for clarity

- Dart SDK version minimum set to 2.17

## 2.0.0-rc2
- Large data Transaction fixes. There was a bug which prevented the crafting of
  large data transactions, i.e transactions with outputs that have PUSHDATA operations
  that pushed more than 65k bytes onto the stack. 

## 2.0.0-rc1

Version 2.x is a major refactor of the internals. 
This includes several breaking changes from the 1.x branch of development. 

The new features :
- A new `TransactionBuilder` class for composing Transactions
- Removal of the old Builder interface which was directly attached to the `Transaction` class
- A complete re-implementation of the Script Interpreter to align with the Bitcoin4J API
- The `Sighash` class now exposes the SigHash Pre-Image; useful when creating `OP_PUSH_TX` spending scripts.
- A new `ScriptBuilder` class to make it easy to create custom locking/unlocking scripts.

## 1.1.1
- downgraded test dependencies to for Flutter compatibility

## 1.1.0
- Exposed the DUST LIMIT and default feePerKb settings on the Transaction so user can manually change these.
- Also exported the TransactionInput class
- Added a property on the Transaction class that exposes the SigHash Preimage after signing.
- Add missing padding for Wif Format
- Add Javascript target support for Flutter/Web
- added additional test coverage for signatures
- added typing and convenience methods to HD key management
- Removed the inline code example
- Dart Version bump to include the 3.x branch


## 1.0.2
- Added convenience method on HDPublicKey for getting SVPublicKey
- Strongly typed hexadecimal string returned for xprivkey in HDPrivateKey

## 1.0.1
Resolved Null-safety warnings on project build

Building an example project threw up some warnings related to the  
pointycastle primitives and null-safety. I've made modifications to library  
implementation to resolve these compiler warnings.

## 1.0.0
- Null-Safety Update
- All dependencies have been upgraded or replaced with null-safe equivalents. 
- Minimum Dart version is now 2.12.2 

## 0.4.3
- Bugfix: Padded s-values to prevent invalid signatures
- Bugfix: Force 256-bit Private Keys to prevent invalid WIF exports
- Update: Updated example code to import latest major version of lib

## 0.4.2
- Bugfix: DataBuilder has script construction error for PUSHDATA transactions. 

## 0.4.1
- Bugfix: Bitcoin-Signed-Messages sometimes generate Signatures with short r-values of only 62 bytes length. This causes compact signatures to fail verification. This is now fixed. 

## 0.4.0
- Fixed a script behaviour bug. When using "add()" to update the SVScript's 
  contents the "toHex()" method failed to serialize the additional content. 
- Added a method to support generic data-only Locking Script Builders. 
- Upgraded the cryptographic library dependency to the new PointyCastle 2.0.1 


## 0.3.3
- Added Electrum-style ECIES (elliptic curve integrated encryption scheme) support

## 0.3.2
- API Exports
- Bug fix on testnet address encoding length
- DataBuilder modifications
- Added detection to TransactionOutput for P2PKH output
- Downgraded the required SDK version to 2.7.0. Aqueduct chokes on Dart 2.8+

## 0.3.1
New Feature
- Added DataLockBuilder to allow composing a simple data output script

Bug Fixes
- Bug fix submited by chen610620 for index bug on signing Transaction Inputs. The bug prevented signing of inputs other than the first one. 

## 0.3.0
This represents a rather major refactor of the way in which the Script Builder   
interface works. I have completely decoupled the creation of Custom Scripts   
from the SDK internals.

*NOTE:* This release is not backwards-compatible with earlier versions   
of the SDK, and contains breaking changes. Please see below.

#### What's New
- P2PKHUnlockBuilder, P2PKHLockBuilder
- P2MSUnlockBuilder, P2MSLockBuilder
- P2SHUnlockBuilder, P2SHLockBuilder
- P2PKLockBuilder, P2PKUnlockBuilder
- Deep refactor of the way that TransactionInput processes scriptSig
- Bugfix related to script serialization
- New API on SVScript to parse and serialize to ASM format
- Resolved one bitcoind MultiSig test vector which failed to pass (it was the last holdout)

Please note that this update makes small but important changes to how one composes a   
Transaction instance in conjunction with an UnlockingScriptBuilder and a LockingScriptBuilder   
instance. Review the example code and test cases to familiarize yourself with the new API.

## 0.2.5-RC1
- Added CLI example app

## 0.2.4-RC1
- Additional test coverage for Signatures
- Minor code refactor to improve code readability in line with linter suggestions

## 0.2.3-RC1
- Minor code refactor to improve code readability in line with linter suggestions

## 0.2.1-RC1
- Minor code refactor to improve code readability in line with linter suggestions

## 0.2.0-RC1
- Completed the API documentation
- Small API changes and cleanup

## 0.1.0-RC1
- Library is now functionally complete
- Script Interpreter Implementation is complete
- Handling of Raw Blocks has been implemented
- Bip39 mnemonics now has complete test coverage
- Minor updates to various APIs

## 0.1.0-alpha2

- Added support for contributed Bip39 mnemonics
- Added support for Bitcoin Signed Messages

## 0.1.0-alpha

- Initial Release
