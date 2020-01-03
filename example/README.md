### Getting Started

#### Install Dart-SDK
Documentation : [https://dart.dev/tools/sdk](https://dart.dev/tools/sdk)
Installation Instructions : [https://dart.dev/get-dart](https://dart.dev/get-dart)

#### Running the app
Navigate to the top-level folder of the `dartsv-cli` project and pull your dependencies
```shell
> pub get
```

Now run the app...

```
> pub run bin/main.dart
```

When you run the app on the CLI it will :
* Print two Addresses on the console
  * Receiving address where you send Testnet coins
  * Spending address where the app will send 10k satoshis automatically
  
You will notice that the app comes ready-to-run with pre-funded testnet addresses. 
You should change the mnemonic and consequently get new addresses for local testing.  

#### Testnet Faucet  
Grab some coins from the faucet located here: [BitcoinSV Testnet Faucet Link](https://bitcoincloud.net/faucet/) (remember to donate some BSV to the dev)

#### BitIndex
Bitindex is a great service which I have used in this example application to :
* Get a list of UTXOs associated with an address
* Broadcast the raw transaction to the testnet

Check them out : [https://www.bitindex.network](https://www.bitindex.network)

#### Feedback
I welcome any and all feedback. Please post a comment on GitHub. 
